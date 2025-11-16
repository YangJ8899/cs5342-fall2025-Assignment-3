import re, json, time, csv
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List
import emoji

import pandas as pd
from atproto import Client
from atproto_client.models.app.bsky.feed.post import GetRecordResponse

from .label import post_from_url

POTENTIAL_SCAM = "Potential URL scam post"

class PolicyLabeler:
    def __init__(self, client: Client, input_dir):
        self.client = client
        self.load_input_dir(input_dir)

    def load_input_dir(self, input_dir):
        """
        Load high-risk and moderate-risk phrases from the specified directory
        """
        # Load high-sus phrases
        self.high_sus_phrases = [
            phrase.lower()
            for phrase in pd.read_csv(f"{input_dir}/high-sus-phrases.csv")["phrase"]
        ]
        
        # Load medium-sus phrases
        self.medium_sus_phrases = [
            phrase.lower()
            for phrase in pd.read_csv(f"{input_dir}/medium-sus-phrases.csv")["phrase"]
        ]
   
    def moderate_post(self, url: str) -> List[str]:
        """
        Apply moderation to the post specified by the given url
        """
        scam_checks = 0
        post = post_from_url(self.client, url)
        ## Do our checks here, if X amount return True, we append the label of POTENTIAL_SCAM to the post
        scam_checks += self.check_profile_for_potential_scam(post)
        scam_checks += self.check_post_for_emojis(post)
        scam_checks += self.check_post_for_sus_language(post)

        if scam_checks >= 5:
            return [POTENTIAL_SCAM]
        return []

    def check_profile_for_potential_scam(self, post: GetRecordResponse) -> int:
        """
        Check if the post author's profile exhibits scam-like characteristics, will not catch
        all accounts so thats why we need to do a cross check with the post content itself
        """
        try:
            scam_score = 0
            author_did = post.uri.split('/')[2]

            profile = self.client.get_profile(author_did)

            followers = profile.followers_count or 0
            following = profile.follows_count or 0
            posts = profile.posts_count or 0

            follow_ratio = (following + 1) // (followers + 1)

            # We check 2 patterns, follower to following ratio, and follower to post ratio

            # Following many, almost no followers (classic scam account)
            if follow_ratio >= 10:
                scam_score += 3
            elif follow_ratio >= 5:
                scam_score += 2

            # Poor follow-back ratio (nobody trusts them)
            if following > 50:
                follow_ratio = followers / following if following > 0 else 0
                if follow_ratio < 0.1:
                    scam_score += 2
            
            # Few/no posts but actively following (just here to spam)
            if posts < 5 and following > 100:
                scam_score += 2
            
            posts_to_followers = posts / max(followers, 1)
            if posts_to_followers >= 100:
                scam_score += 3
            elif posts_to_followers >= 50:
                scam_score += 2
            elif posts_to_followers >= 10:
                scam_score += 1

            return scam_score
        except Exception as e:
            print(f"Error checking profile for scam: {e}")
            return 0

    def check_post_for_emojis(self, post: GetRecordResponse) -> int:
        """
        Check if the post text contains many emojis (a pattern often used by scam accounts).
        """
        scam_score = 0
        try:
            text = getattr(post.value, "text", "")
            # Count how many emoji characters appear in the post
            emoji_count = sum(char in emoji.EMOJI_DATA for char in text)

            # Heuristic rule: 
            if emoji_count <= 2:
                scam_score = 0
            elif 2 < emoji_count < 5:
                scam_score = 1
            else:  # emoji_count > 5
                scam_score = 2
            
            return scam_score
        
        except Exception as e:
            print(f"Error checking emojis in post: {e}")
            return 0
    
    def check_post_for_sus_language(self, post: GetRecordResponse) -> int:
        """
        Check if the post content contains scam-related keywords and phrases.
        Returns a score (0-3) based on how suspicious the content is.
        """
        try:
            text = getattr(post.value, "text", "").lower()
            
            if not text:
                return 0
            
            scam_score = 0
            
            # If we have any phrases from the highest suspicious list, we return 3
            for phrase in self.high_sus_phrases:
                if phrase in text:
                    return 3
            
            # We add 1 for every medium suspicious phrase, cap at 3
            moderate_count = 0
            for phrase in self.medium_sus_phrases:
                if phrase in text:
                    moderate_count += 1
            
            if moderate_count >= 3:
                scam_score = 2
            elif moderate_count >= 2:
                scam_score = 1
            
            return min(scam_score, 3)  # Cap at 3
            
        except Exception as e:
            print(f"Error checking post content for scam: {e}")
            return 0
