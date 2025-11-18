import re, json, time, csv
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List
import emoji

import pandas as pd
from atproto import Client
from atproto_client.models.app.bsky.feed.post import GetRecordResponse
from atproto_client.models.app.bsky.richtext.facet import Link

from .label import post_from_url

# Label to apply to posts identified as potential scams
POTENTIAL_SCAM = "Potential URL scam post"

class PolicyLabeler:
    """
    Automated content moderation labeler for detecting URL scam posts on Bluesky.
    
    Uses a multi-faceted approach combining:
    - Profile analysis (follower/following ratios, post counts)
    - Content analysis (emojis, suspicious phrases, hashtags)
    - URL checking (shortened URLs, known malicious domains)
    
    Posts are assigned points based on suspicious indicators and flagged if they
    score >= 5 points AND contain a URL.
    """
    
    def __init__(self, client: Client, input_dir):
        """
        Initialize the labeler with a Bluesky client and input directory.
        
        Args:
            client: Authenticated Bluesky client for API calls
            input_dir: Directory containing CSV files and synthetic test data
        """
        self.client = client
        
        # Load suspicious phrases and malicious URLs from CSV files
        self.load_input_dir(input_dir)

        # Load synthetic test posts from JSON file (if available)
        self.synthetic_posts = {}
        synthetic_file = Path(input_dir) / "synthetic_posts.json"
        if synthetic_file.exists():
            with open(synthetic_file, 'r') as f:
                self.synthetic_posts = json.load(f)

    def load_input_dir(self, input_dir):
        """
        Load suspicious phrase dictionary and malicious URL database from CSV files.
        
        Files loaded:
        - medium-sus-phrases.csv: Common scam phrases
        - malicious_phish.csv: Known malicious/phishing URLs
        
        Args:
            input_dir: Directory containing the CSV files
        """
        # Load dictionary of suspicious phrases (e.g., "guaranteed profit", "join discord")
        self.medium_sus_phrases = [
            phrase.lower()
            for phrase in pd.read_csv(f"{input_dir}/medium-sus-phrases.csv")["phrase"]
        ]

        # Load known malicious URLs and normalize them (strip protocol, lowercase)
        df = pd.read_csv(f"{input_dir}/malicious_phish.csv")
        self.malicious_urls = [
            re.sub(r"^https?://", "", u.lower()).strip()
            for u in df["url"].tolist()
        ]
   
    def moderate_post(self, url: str) -> List[str]:
        """
        Main entry point: analyze a post and return applicable labels.
        
        For real Bluesky posts, fetches the post and runs all checks.
        For synthetic test posts (URLs starting with "SYNTHETIC"), uses mock data.
        
        Args:
            url: Either a Bluesky post URL or a synthetic post ID (e.g., "SYNTHETIC_001")
            
        Returns:
            List of labels (["Potential URL scam post"] if flagged, [] otherwise)
        """
        # Handle synthetic test posts differently
        if url.startswith("SYNTHETIC"):
            return self.moderate_synthetic(url)
        
        # Fetch the real post from Bluesky
        post = post_from_url(self.client, url)
        
        # Run all checks and accumulate points
        scam_checks = 0
        scam_checks += self.check_profile_for_potential_scam(post)
        scam_checks += self.check_post_for_emojis(post)
        scam_checks += self.check_post_for_sus_language(post)
        scam_checks += self.check_post_for_malicious_urls(post) 
        scam_checks += self.check_post_for_shortened_urls(post)
        
        # Check if post contains any URL (requirement for flagging)
        has_url = self.check_post_for_any_url(post)
        
        # Flag if score >= 5 AND post contains a URL
        if scam_checks >= 5 and has_url:
            return [POTENTIAL_SCAM]
        return []

    def moderate_synthetic(self, synthetic_id: str) -> List[str]:
        """
        Handle synthetic test posts by creating mock post and profile objects.
        
        Allows testing without making API calls or creating real posts.
        Synthetic posts are defined in synthetic_posts.json.
        
        Args:
            synthetic_id: ID of the synthetic post (e.g., "SYNTHETIC_001")
            
        Returns:
            List of labels (same as moderate_post)
        """
        if synthetic_id not in self.synthetic_posts:
            print(f"Warning: Synthetic post {synthetic_id} not found")
            return []
        
        synthetic_data = self.synthetic_posts[synthetic_id]
        
        # Import mocking utilities
        from unittest.mock import Mock, patch
        
        # Create mock post object with synthetic text
        mock_post = Mock()
        mock_post.value = Mock()
        mock_post.value.text = synthetic_data['text']
        mock_post.value.facets = []
        mock_post.uri = f"at://synthetic/{synthetic_id}"
        
        # Extract URLs from text and create mock facets
        # (Bluesky stores URLs as both text and structured facets)
        urls_in_text = re.findall(r'https?://[^\s]+', synthetic_data['text'])
        if urls_in_text:
            mock_facets = []
            for url in urls_in_text:
                mock_facet = Mock()
                mock_feature = Mock(spec=Link)
                mock_feature.uri = url
                mock_facet.features = [mock_feature]
                mock_facets.append(mock_facet)
            mock_post.value.facets = mock_facets
        
        # Create mock profile with synthetic metrics
        mock_profile = Mock()
        mock_profile.followers_count = synthetic_data['profile']['followers']
        mock_profile.follows_count = synthetic_data['profile']['following']
        mock_profile.posts_count = synthetic_data['profile']['posts']
        
        # Mock the get_profile method to return our synthetic profile
        with patch.object(self.client, 'get_profile', return_value=mock_profile):
            # Run all checks (same as real posts)
            scam_checks = 0
            scam_checks += self.check_profile_for_potential_scam(mock_post)
            scam_checks += self.check_post_for_emojis(mock_post)
            scam_checks += self.check_post_for_sus_language(mock_post)
            scam_checks += self.check_post_for_malicious_urls(mock_post)
            scam_checks += self.check_post_for_shortened_urls(mock_post)
            has_url = self.check_post_for_any_url(mock_post)
            
            # Apply same threshold as real posts
            if scam_checks >= 5 and has_url:
                return [POTENTIAL_SCAM]
        return []
        
    def check_profile_for_potential_scam(self, post: GetRecordResponse) -> int:
        """
        Analyze the post author's profile for scam indicators.
        
        Checks for:
        - Mass following with few followers (bot pattern)
        - Poor follow-back ratio (nobody trusts them)
        - High post count with very few followers (spam bot)
        - Extreme posts-to-followers ratio (posting into the void)
        
        Args:
            post: The post object containing author information
            
        Returns:
            Score from 0-10+ based on profile suspiciousness
        """
        try:
            scam_score = 0
            
            # Extract author DID from post URI
            author_did = post.uri.split('/')[2]

            # Fetch author's profile from Bluesky
            profile = self.client.get_profile(author_did)

            # Extract metrics (default to 0 if None)
            followers = profile.followers_count or 0
            following = profile.follows_count or 0
            posts = profile.posts_count or 0

            # Calculate following-to-followers ratio
            # Add 1 to avoid division by zero
            follow_ratio = (following + 1) // (followers + 1)

            # Check 1: Mass following pattern (following many, few followers)
            if follow_ratio >= 10:
                scam_score += 3  # Extreme ratio
            elif follow_ratio >= 5:
                scam_score += 2  # High ratio

            # Check 2: Poor follow-back ratio (nobody follows them back)
            if following > 50:
                follow_back_ratio = followers / following if following > 0 else 0
                if follow_back_ratio < 0.1:  # Less than 10% follow back
                    scam_score += 2
            
            # Check 3: Posts-to-followers ratio (posting with no audience)
            posts_to_followers = posts / max(followers, 1)
            if posts_to_followers >= 100:  # 100+ posts per follower
                scam_score += 3
            elif posts_to_followers >= 40:  # 40+ posts per follower
                scam_score += 2
            elif posts_to_followers >= 10:  # 10+ posts per follower
                scam_score += 1

            # Check 4: High-volume spam bots (many posts, almost no followers)
            if posts >= 100 and followers < 5:
                scam_score += 3
            elif posts >= 50 and followers < 10:
                scam_score += 2
            elif posts >= 20 and followers < 5:
                scam_score += 1
        
            return scam_score
            
        except Exception as e:
            print(f"Error checking profile for scam: {e}")
            return 0

    def check_post_for_emojis(self, post: GetRecordResponse) -> int:
        """
        Check for excessive emoji usage (common in spam posts).
        
        Scam posts often use many emojis to grab attention and appear
        more casual/legitimate (e.g., 🚀💰🔥💎).
        
        Args:
            post: The post object
            
        Returns:
            0 points (0-2 emojis), 1 point (3-4 emojis), or 2 points (5+ emojis)
        """
        try:
            text = getattr(post.value, "text", "")
            
            # Count emoji characters using emoji library
            emoji_count = sum(char in emoji.EMOJI_DATA for char in text)

            # Score based on emoji count
            if emoji_count <= 2:
                return 0  # Normal usage
            elif 2 < emoji_count < 5:
                return 1  # Moderate usage
            else:  # emoji_count >= 5
                return 2  # Excessive usage (spam indicator)
        
        except Exception as e:
            print(f"Error checking emojis in post: {e}")
            return 0
    
    def check_post_for_sus_language(self, post: GetRecordResponse) -> int:
        """
        Check post text for suspicious phrases and hashtag spam.
        
        Looks for:
        - Suspicious phrases from dictionary (e.g., "guaranteed profit", "join discord")
        - Excessive hashtag usage (common in spam to increase visibility)
        
        Args:
            post: The post object
            
        Returns:
            Score from 0-3 based on suspicious language and hashtags
        """
        try:
            text = getattr(post.value, "text", "").lower()
            
            if not text:
                return 0
            
            scam_score = 0
            
            # Check for suspicious phrases from dictionary
            moderate_count = 0
            for phrase in self.medium_sus_phrases:
                if phrase in text:
                    moderate_count += 1
            
            # Score based on number of suspicious phrases found
            if moderate_count >= 3:
                scam_score = 3  # Multiple scam indicators
            elif moderate_count >= 2:
                scam_score = 2  # Some indicators
            elif moderate_count >= 1:
                scam_score = 1  # Single indicator
            
            # Check for hashtag spam
            hashtag_count = text.count('#')
        
            if hashtag_count >= 10:
                scam_score += 3  # Extreme hashtag spam
            elif hashtag_count >= 7:
                scam_score += 2  # Very high hashtag use
            elif hashtag_count >= 4:
                scam_score += 1  # Moderately high hashtag use
            
            # Cap total score at 3 for this check
            return min(scam_score, 3)
            
        except Exception as e:
            print(f"Error checking post content for scam: {e}")
            return 0
        
    def extract_all_urls(self, post: GetRecordResponse) -> List[str]:
        """
        Extract all URLs from a post, checking both text and facets.
        
        Bluesky stores URLs in two places:
        1. Plain text (visible in post.value.text)
        2. Facets (structured metadata for links)
        
        This ensures we catch all URLs, including those not visible in plain text.
        
        Args:
            post: The post object
            
        Returns:
            List of URLs found in the post
        """
        urls = []
        
        # Extract URLs from plain text using regex
        text = getattr(post.value, "text", "") or ""
        urls_in_text = re.findall(r'https?://[^\s]+', text)
        urls.extend(urls_in_text)
        
        # Extract URLs from facets (Bluesky's structured link format)
        if hasattr(post.value, 'facets') and post.value.facets:
            for facet in post.value.facets:
                if hasattr(facet, 'features'):
                    for feature in facet.features:
                        # Only Link features have URIs (not Mention or Tag features)
                        if isinstance(feature, Link):
                            urls.append(feature.uri)
        
        return urls
    
    def check_post_for_malicious_urls(self, post: GetRecordResponse) -> int:
        """
        Check if post contains any known malicious/phishing URLs.
        
        Compares URLs in the post against a database of known malicious domains
        from malicious_phish.csv.
        
        Args:
            post: The post object
            
        Returns:
            3 points if malicious URL found, 0 otherwise
        """
        try:
            # Extract all URLs from the post
            urls_in_post = self.extract_all_urls(post)

            # Normalize URLs by stripping protocol (http://, https://)
            normalized_urls = [
                re.sub(r'^https?://', '', url).strip()
                for url in urls_in_post
            ]

            # Check each URL against known malicious domains
            for post_url in normalized_urls:
                for bad_url in self.malicious_urls:
                    if bad_url in post_url:
                        return 3  # Maximum risk score for known malicious URL

            return 0

        except Exception as e:
            print(f"Error checking malicious URLs: {e}")
            return 0
    
    def check_post_for_any_url(self, post: GetRecordResponse) -> bool:
        """
        Check if the post contains ANY URL at all.
        
        This is a requirement for flagging - we only label posts as scams if they
        contain a URL. This prevents false positives on casual posts that happen
        to use suspicious language.
        
        Args:
            post: The post object
            
        Returns:
            True if post contains at least one URL, False otherwise
        """
        try:
            urls = self.extract_all_urls(post)
            
            # Debug output to help with testing
            if urls:
                print(f"URLs found: {urls}")
            
            return len(urls) > 0

        except Exception as e:
            print(f"Error checking for any URL: {e}")
            return False

    def check_post_for_shortened_urls(self, post: GetRecordResponse) -> int:
        """
        Check if post contains shortened URLs (bit.ly, t.me, etc.).
        
        URL shorteners are commonly used in scams to:
        - Hide the actual destination
        - Make links look cleaner/more legitimate
        - Bypass URL-based filtering
        
        Common shorteners: bit.ly, t.me, tinyurl.com, goo.gl, etc.
        
        Args:
            post: The post object
            
        Returns:
            2 points if shortened URL found, 0 otherwise
        """
        try:
            urls_in_post = self.extract_all_urls(post)

            if not urls_in_post:
                return 0

            # List of common URL shortener domains
            shortened_domains = [
                "bit.ly",
                "t.co",
                "t.me",          # Telegram
                "tinyurl.com",
                "goo.gl",
                "ow.ly",
                "is.gd",
                "buff.ly",
                "shorturl.at",
                "rebrand.ly",
                "cutt.ly",
                "shrtco.de",
                "rb.gy",
                "adf.ly",
                "bit.do",
                "short.com"
            ]
            
            # Check if any URL uses a shortener domain
            for url in urls_in_post:
                for short in shortened_domains:
                    if short in url:
                        return 2  # Shortened URL detected

            return 0

        except Exception as e:
            print(f"Error checking shortened URLs: {e}")
            return 0