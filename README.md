# Bluesky Content Moderation - Assignment 3

## Group Information
**Group Members:**
- Yang Ji
- Alex Xiong
- Konrad Kopko
- Hanqi Guo

---

## Project Overview
This project implements an automated content moderation labeler for Bluesky that detects potential URL scam posts. The labeler uses a multi-faceted approach combining profile analysis, content analysis, and URL checking to identify suspicious posts.

---

## Files Submitted

### Core Implementation Files

#### `policy_labeler.py`
Main implementation of the scam detection labeler. Contains the `PolicyLabeler` class with the following key methods:
- `moderate_post()`: Entry point that orchestrates all checks and returns labels
- `check_profile_for_potential_scam()`: Analyzes account metrics (follower/following ratio, post count, account age indicators)
- `check_post_for_emojis()`: Detects excessive emoji usage common in spam
- `check_post_for_sus_language()`: Matches text against suspicious phrase dictionaries and counts hashtags
- `check_post_for_malicious_urls()`: Checks URLs against known phishing database
- `check_post_for_shortened_urls()`: Detects URL shorteners (bit.ly, t.me, etc.)
- `check_post_for_any_url()`: Verifies presence of URLs (requirement for flagging)
- `extract_all_urls()`: Helper method to extract URLs from both post text and Bluesky facets
- `moderate_synthetic()`: Handles synthetic test posts for evaluation

The labeler assigns points for each suspicious indicator and flags posts that score ≥5 points AND contain a URL.

### Data Files

#### `data/medium-sus-phrases.csv`
Dictionary of suspicious phrases commonly used in scams (click here, limited time, guaranteed profit, join our discord, etc.). Posts containing 3+ phrases receive maximum content score.

#### `data/malicious_phish.csv`
Database of known malicious/phishing URLs. Posts containing these URLs are immediately flagged with high confidence.

#### `data/synthetic_posts.json`
Comprehensive test dataset containing synthetic posts

Each entry includes post text, profile metrics, expected label, and explanation.

#### `data.csv`
Combined test dataset with URLs to both real Bluesky posts and synthetic test cases. Format:
```csv
URL,Labels
https://bsky.app/profile/.../post/...,["Potential URL scam post"]
SYNTHETIC_001,["Potential URL scam post"]
```

### Starter Code Files (Provided)
- `test_labeler.py`: Testing script that runs the labeler against test dataset
- `label.py`: Helper functions for post fetching and labeling
- Other utility files from the starter code

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- Bluesky account credentials

### Install Dependencies
```bash
pip install atproto pandas python-dotenv emoji
```

### Environment Configuration
Create a `.env` file in the project root:
```
USERNAME=your_bluesky_handle
PW=your_bluesky_password
```

---

## How to Run Tests

### Basic Test Run
Run the labeler against all test posts (real + synthetic):
```bash
python test_labeler.py ./labeler-inputs ./test-data/data.csv
```

**Expected Output:**
```
URLs found: [...]
The labeler produced X correct labels assignments out of Y
Overall ratio of correct label assignments: 0.XX
```

## Understanding Test Results

### Scoring System
The labeler uses a point-based system:

| Check | Points Awarded |
|-------|----------------|
| **Profile Checks** | 0-10+ points |
| - Extreme following/follower ratio (≥10:1, following ≥100) | +3 |
| - High following/follower ratio (≥5:1, following ≥50) | +2 |
| - Poor follow-back ratio (<10%, following >50) | +2 |
| - Posts-to-followers ratio (≥100) | +3 |
| - Posts-to-followers ratio (≥40) | +2 |
| - Posts-to-followers ratio (≥10) | +1 |
| - High posts, very low followers (100+ posts, <5 followers) | +3 |
| **Emoji Check** | 0-2 points |
| - 5+ emojis | +2 |
| - 3-4 emojis | +1 |
| **Content Checks** | 0-3 points |
| - 3+ suspicious phrases | +3 |
| - 2 suspicious phrases | +2 |
| - 1 suspicious phrase | +1 |
| - 10+ hashtags | +3 |
| - 7-9 hashtags | +2 |
| - 4-6 hashtags | +1 |
| **URL Checks** | 0-3 points |
| - Known malicious URL | +3 |
| - Shortened URL (bit.ly, t.me, etc.) | +2 |

**Threshold:** Posts with ≥5 points AND containing a URL are labeled as "Potential URL scam post"
---

## Customization

### Adjusting Sensitivity
Edit threshold in `policy_labeler.py`:
```python
# Line ~50 in moderate_post()
if scam_checks >= 5 and has_url:  # Change 5 to 4 (more sensitive) or 6 (less sensitive)
    return [POTENTIAL_SCAM]
```

### Adding Custom Suspicious Phrases
Edit `data/medium-sus-phrases.csv`:
```csv
phrase
your_new_phrase
another_phrase
```

### Adding Known Malicious URLs
Edit `data/malicious_phish.csv`:
```csv
url
https://scam-site.com
https://phishing-example.com
```

## Adding Test Posts

### Adding Real Bluesky Posts

To add real posts from Bluesky to your test dataset:

#### Method 1: Manual Collection
1. Navigate to the post you want to test on Bluesky web interface
2. Copy the full URL (format: `https://bsky.app/profile/[handle]/post/[post_id]`)
3. Manually label the post (is it a scam or not?)
4. Add to `test_posts.csv`:
```csv
URL,Labels
https://bsky.app/profile/scammer123.bsky.social/post/abc123,["Potential URL scam post"]
https://bsky.app/profile/legituser.bsky.social/post/xyz789,[]
```

### Adding Synthetic Test Posts

Synthetic posts allow you to test specific edge cases without relying on real posts.

#### Step 1: Add to `data/synthetic_posts.json`
```json
{
  "SYNTHETIC_051": {
    "text": "Your post text here with emojis 🚀💰 and hashtags #crypto #trading",
    "profile": {
      "posts": 100,
      "followers": 50,
      "following": 200
    },
    "expected": ["Potential URL scam post"],
    "reason": "Explanation of why this should/shouldn't be flagged"
  }
}
```

#### Step 2: Add to `test_posts.csv`
```csv
URL,Labels
SYNTHETIC_051,["Potential URL scam post"]
```
---

## Project Structure
```
bluesky-assign3/
├── labeler-inputs/
│   ├── medium-sus-phrases.csv       # Suspicious phrase dictionary
│   ├── malicious_phish.csv          # Known malicious URLs
│   └── synthetic_posts.json         # Synthetic test cases
├── pylabel                     
│   ├── label.py                     # Helper functions (provided)     
│   └── policy_labeler.py            # Main labeler implementation
├── test-data                         
│   └── data.csv                     # Combined test dataset
├── test_labeler.py                  # Test runner (provided)
├── .env                             # Credentials (not committed)
├── README.md                        # This file
└── [other starter code files]
```

---
>>>>>>> myrepo/main
