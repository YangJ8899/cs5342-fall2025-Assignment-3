"""Implementation of automated moderator"""

from pathlib import Path
from typing import List

import pandas as pd
from atproto import Client
from atproto_client.models.app.bsky.feed.post import GetRecordResponse

from perception import hashers
from .label import post_from_url, images_from_post

T_AND_S_LABEL = "t-and-s"
DOG_LABEL = "dog"
THRESH = 0.3

class AutomatedLabeler:
    """Automated labeler implementation"""

    def __init__(self, client: Client, input_dir):
        self.client = client
        self.load_input_dir(input_dir)

    def load_input_dir(self, input_dir):
        """
        Load t-and-s/news domains and dog images from the specified directory
        """
        self.t_and_s_domains = pd.read_csv(f"{input_dir}/t-and-s-domains.csv")[
            "Domain"
        ].tolist()
        self.t_and_s_words = [
            word.lower()
            for word in pd.read_csv(f"{input_dir}/t-and-s-words.csv")["Word"]
        ]
        self.domain_to_source = {}
        source_df = pd.read_csv(f"{input_dir}/news-domains.csv")
        for i in range(source_df.shape[0]):
            self.domain_to_source[source_df["Domain"][i]] = source_df["Source"][i]
        hasher = hashers.PHash()
        self.phashes = []
        for path in Path(f"{input_dir}/dog-list-images").iterdir():
            self.phashes.append(hasher.compute(str(path)))
   
    def moderate_post(self, url: str) -> List[str]:
        """
        Apply moderation to the post specified by the given url
        """
        result = []
        post = post_from_url(self.client, url)
        result += self.check_t_and_s_words_domains(post)
        result += self.check_sources(post)
        result += self.check_images(post)
        return result

    def check_t_and_s_words_domains(self, post: GetRecordResponse) -> List[str]:
        """
        Check the post for t-and-s words and return labels if
        appropriate.
        """
        for word in self.t_and_s_words:
            if word in post.value.text.lower():
                return [T_AND_S_LABEL]
        for domain in self.t_and_s_domains:
            if domain in post.value.text:
                return [T_AND_S_LABEL]
        return []

    def check_sources(self, post: GetRecordResponse) -> List[str]:
        """
        Check the post if it contains links to news articles and
        return labels if appropriate.
        """
        result = []
        for domain, source in self.domain_to_source.items():
            if domain in post.value.text:
                result.append(source)
        return result

    def check_images(self, post: GetRecordResponse) -> List[str]:
        """
        Check this post if it contains images and compare against
        image dog-list, attaching labels if appropriate.
        """
        post_images = images_from_post(post)
        hasher = hashers.PHash()
        for post_image in post_images:
            post_image_hash = hasher.compute(post_image)
            for dog_hash in self.phashes:
                if hasher.compute_distance(post_image_hash, dog_hash) <= THRESH:
                    return [DOG_LABEL]
        return []
