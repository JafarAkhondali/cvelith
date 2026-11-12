import base64
import os
import random
from copy import deepcopy
from typing import List, Dict, Optional

import requests
import time
from datetime import datetime, timedelta

from cvevibes.settings import GITHUB_TOKEN

GITHUB_API_BASE_URL = "https://api.github.com"

class GitHubAPI:
    def __init__(self):
        self.headers = {
            'Authorization': f'Bearer {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json',
        }

    def get_repo(self, repo_name):
        response = self._request(f"{GITHUB_API_BASE_URL}/repos/{repo_name}")
        return response.json()

    def search_repositories(self, query, page=1, per_page=100, sort='updated'):
        raise Exception("Deprecated")
        """Search repositories based on the query with pagination support."""
        url = f"{GITHUB_API_BASE_URL}/search/repositories"
        query = f"\"{query}\" fork:false"
        params = {'q': query, 'sort': sort, 'page': page, 'per_page': per_page}
        # params = {'q': f"\"{query}\" in:name,description fork:false size:>0", 'sort': sort, 'page': page, 'per_page': per_page}
        return self._request(url, params=params)

    def search_repositories(self, query, start_date=None, end_date=None, per_page=100, sort='created',
                            date_split_days=1):
        raise Exception("Deprecated")
        """
        Search repositories with date-based splitting to bypass 1000 result limit.

        Args:
            query: Search query string
            start_date: Start date (datetime object or 'YYYY-MM-DD' string)
            end_date: End date (datetime object or 'YYYY-MM-DD' string)
            per_page: Results per page (max 100)
            sort: Sort field (created, updated, stars, etc.)
            date_split_days: Number of days to split search into (default 1 day)

        Returns:
            List of all repositories found
        """
        url = f"{GITHUB_API_BASE_URL}/search/repositories"
        all_results = []

        # Parse dates if provided as strings
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, '%Y-%m-%d')

        # Default end_date to today if not provided
        if not end_date:
            end_date = datetime.now()

        # Default start_date to one week ago if not provided
        if not start_date:
            start_date = end_date - timedelta(days=7)

        current_date = start_date

        # Split search into date ranges to bypass 1000 limit
        while current_date < end_date:
            next_date = current_date + timedelta(days=date_split_days)

            # Build query with date range
            base_query = f'"{query}" fork:false'
            date_range = f'created:{current_date.strftime("%Y-%m-%d")}..{next_date.strftime("%Y-%m-%d")}'
            full_query = f'{base_query} {date_range}'

            # Paginate through results for this date range
            page = 1
            while True:
                params = {
                    'q': full_query,
                    'sort': sort,
                    'page': page,
                    'per_page': per_page
                }

                response = self._request(url, params=params)
                items = response.get('items', [])

                all_results.extend(items)

                # Check if there are more pages
                total_count = response.get('total_count', 0)
                if page * per_page >= total_count or len(items) == 0:
                    break

                page += 1

            current_date = next_date

        return all_results

    def get_readme_content(self, repo_full_name):
        """Fetch README content from the repository's default branch."""
        url = f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/readme"
        response = self._request(url)

        if response.status_code == 200:
            data = response.json()
            encoding = data.get('encoding')
            content = data.get('content', '')
            if encoding == 'base64':
                # Decode the base64 content
                readme_content = base64.b64decode(content).decode('utf-8', errors='ignore').replace("\x00", "")
                return readme_content
        return ""
    def get_paginated_data(self, url):
        """Fetch paginated data for stars, forks, or watchers."""
        page = 1
        all_data = []
        while True:
            response = self._request(url, params={'page': page, 'per_page': 100})
            if not response or response.status_code != 200:
                break
            data = response.json()
            all_data.extend(data)
            if len(data) < 100:
                break
            page += 1
        return all_data

    def _request(self, url, params=None, max_retries=3, base_delay=1):
        """
        Handle API requests with rate limit management and retry logic.

        Args:
            url (str): The API endpoint URL
            params (dict, optional): Query parameters for the request
            max_retries (int, optional): Maximum number of retry attempts for network issues
            base_delay (int, optional): Base delay in seconds for exponential backoff

        Returns:
            requests.Response: The API response

        Raises:
            requests.HTTPError: If the request fails after all retries
        """
        headers = deepcopy(self.headers)
        if url.endswith('/stargazers'):
            headers['Accept'] = 'application/vnd.github.v3.star+json'

        retries = 0
        while retries <= max_retries:
            try:
                response = requests.get(url, headers=headers, params=params, timeout=10)

                # Handle rate limiting
                if response.status_code == 403 and 'X-RateLimit-Reset' in response.headers:
                    print(response)
                    reset_time = int(response.headers["X-RateLimit-Reset"])
                    sleep_time = max(int(reset_time - time.time()), 61)
                    print(f"Sleeping for {sleep_time}")
                    time.sleep(sleep_time)
                    response = requests.get(url, headers=headers, params=params, timeout=10)
                    print(response)

                # Raise error for non-404 error status codes
                if response.status_code != 404:
                    response.raise_for_status()

                # If we got here, the request was successful
                return response

            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.RequestException) as e:
                retries += 1

                # If we've reached max retries, raise the exception
                if retries > max_retries:
                    raise

                # Calculate delay with exponential backoff (1s, 2s, 4s, etc.)
                delay = base_delay * (2 ** (retries - 1))

                # Add jitter to avoid thundering herd problem (±20% variation)
                jitter = random.uniform(0.8, 1.2)
                sleep_time = delay * jitter

                time.sleep(sleep_time)

                # Continue to next iteration to retry

class GitHubSearcher:
    """
    Intelligent GitHub repository search using binary search date splitting.
    Respects rate limits and handles the 1000-result API limit correctly.
    """

    def __init__(self, token: str, requests_per_hour: int = 4000):
        self.token = token
        self.base_url = "https://api.github.com/search/repositories"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.api_calls = 0
        self.rate_limit_reset = None
        self.rate_limit_remaining = None

        # Calculate delay between requests to stay under rate limit
        # GitHub allows 30 requests per minute for authenticated search
        self.min_delay = 60.0 / 30  # ~2 seconds between requests
        self.last_request_time = 0

    def _respect_rate_limit(self):
        """Wait if necessary to respect rate limits"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay:
            wait_time = self.min_delay - elapsed
            print(f"⏱️  Rate limit: waiting {wait_time:.1f}s...")
            time.sleep(wait_time)

    def _search(self, query: str, start_date: datetime, end_date: datetime) -> Dict:
        """Make a single search request with pagination to get all results"""
        date_range = f"created:{start_date.strftime('%Y-%m-%d')}..{end_date.strftime('%Y-%m-%d')}"
        full_query = f'"{query}" fork:false {date_range}'

        all_items = []
        page = 1

        while True:
            self._respect_rate_limit()
            self.last_request_time = time.time()

            params = {
                'q': full_query,
                'per_page': 100,
                'page': page
            }

            self.api_calls += 1
            response = requests.get(self.base_url, headers=self.headers, params=params)

            # Track rate limits
            if 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                reset_timestamp = int(response.headers['X-RateLimit-Reset'])
                response = requests.get(self.base_url, headers=self.headers, params=params)
                self.rate_limit_reset = datetime.fromtimestamp(reset_timestamp)

            if response.status_code>=400:
                print(response.status_code)
                print(response.headers)
                print(response.content)
            response.raise_for_status()
            data = response.json()

            items = data.get('items', [])
            if not items:
                break

            all_items.extend(items)
            total_count = data.get('total_count', 0)

            # Stop if we've paginated through all available results
            # GitHub caps at 1000 total, but we can get all of them by paginating
            if page * 100 >= min(total_count, 1000) or len(items) == 0:
                break

            page += 1

        return {
            'items': all_items,
            'total_count': len(all_items),
            'capped_at_1000': len(all_items) == 1000
        }

    def _binary_search_dates(self, query: str, start_date: datetime, end_date: datetime,
                             results: List[Dict], depth: int = 0) -> List[Dict]:
        """
        Recursively search date ranges using binary search strategy.
        Only splits when results hit 1000 (the API limit).
        """
        indent = "  " * depth

        try:
            data = self._search(query, start_date, end_date)
        except Exception as e:
            print(f"{indent}❌ Error searching {start_date} to {end_date}: {e}")
            return results

        items = data.get('items', [])
        capped = data.get('capped_at_1000', False)

        print(f"{indent}📊 {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}: "
              f"{len(items)} results (call #{self.api_calls}, remaining: {self.rate_limit_remaining})")

        # If we got less than 1000 results, we have them all
        if not capped:
            results.extend(items)
            return results

        # If we hit the 1000 limit, split the date range and recurse
        print(f"{indent}⚠️  Hit 1000 limit! Splitting date range...")
        mid_date = start_date + (end_date - start_date) / 2

        # Search first half
        self._binary_search_dates(query, start_date, mid_date, results, depth + 1)

        # Search second half
        self._binary_search_dates(query, mid_date, end_date, results, depth + 1)

        return results

    def search(self, query: str, start_date: Optional[str] = None,
               end_date: Optional[str] = None) -> List[Dict]:
        """
        Search repositories with intelligent date splitting and rate limit respect.

        Args:
            query: Search query string
            start_date: Start date as 'YYYY-MM-DD' (default: 30 days ago)
            end_date: End date as 'YYYY-MM-DD' (default: today)

        Returns:
            List of repository dictionaries
        """
        # Parse dates
        end = datetime.strptime(end_date, '%Y-%m-%d') if end_date else datetime.now()
        start = datetime.strptime(start_date, '%Y-%m-%d') if start_date else end - timedelta(days=30)

        print(f"🔍 Searching for: {query}")
        print(f"📅 Date range: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}\n")

        self.api_calls = 0
        results = []
        results = self._binary_search_dates(query, start, end, results)

        # Deduplicate by repo ID
        seen = set()
        unique = []
        for repo in results:
            if repo['id'] not in seen:
                seen.add(repo['id'])
                unique.append(repo)

        print(f"\n✅ Total unique repos found: {len(unique)}")
        print(f"📞 Total API calls: {self.api_calls}")
        if self.rate_limit_reset:
            print(f"⏱️  Rate limit resets at: {self.rate_limit_reset}")

        return unique
