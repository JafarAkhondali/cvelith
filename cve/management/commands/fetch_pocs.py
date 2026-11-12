import sys
import time
from datetime import datetime

from django.core.management.base import BaseCommand
from django.db.models import Max
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from tqdm import tqdm
from cve.models import CVE, POC, Star, Fork, Watch, CVEPOCMapping
from cve.datasources.github_api import GitHubAPI, GitHubSearcher
from cve.utils.textprocess import extract_cves
from cvevibes.settings import MAX_CVES_PER_REPO, GITHUB_TOKEN

GITHUB_API_BASE_URL = "https://api.github.com"

class Command(BaseCommand):
    help = "Fetch and update PoC repositories, readme, and historical data from GitHub."

    def add_arguments(self, parser):
        parser.add_argument('--start-year', type=int, help="Start year for CVE search pattern CVE-{start_year}-*}")
        parser.add_argument('--end-year', type=int, help="End year for CVE search pattern CVE-{end_year}-*}")

        parser.add_argument(
            '--cve',
            type=str,
            help="Optional CVE number for single CVE update"
        )

        parser.add_argument(
            '--sync-pocs',
            action='store_true',
            help="Only sync existing PoC data"
        )


        parser.add_argument(
            '--start-date-sync',
            type=str,
            required=False,
            help="Optional date for start of syncing start (e.g. --start-date-sync \"2025-11-20\")"
        )

    def handle(self, *args, **options):

        start_year = options['start_year']
        end_year = options['end_year']
        custom_cve = options.get('cve')
        sync_pocs = options.get('sync_pocs')
        start_date_sync = options.get('start_date_sync')

        github_api = GitHubAPI()

        if custom_cve:
            self.search_and_process_pocs(github_api, custom_cve)
            self.stdout.write(f"Finished processing {custom_cve}!")
            return


        if sync_pocs:
            self.sync_issues(github_api)
            return

        for year in range(start_year, end_year + 1):
            print(f"Processing {year}")
            self.search_and_process_pocs(github_api,f'CVE-{year}-', start_date_sync=start_date_sync)

            # unique_cves = (CVEPOCMapping.objects.filter(cve_id__startswith=f"CVE-{year}-")
            #                .values_list('cve_id').distinct())
            # for cve in unique_cves: #TODO: Hopefully we can ignore this.
            #     self.search_and_process_pocs(github_api, cve[0])
        self.stdout.write("Finished processing repositories!")


    def sync_issues(self, github_api):
        issues_counter = {'issues_enabled': 0, 'issues_disabled':0}
        for repo in tqdm(POC.objects.all()):
            try:
                if not repo.link.startswith("https://github.com/"):
                    print(f"Skipping {repo}, invalid link! ")
                    continue

                repo_name = repo.link[len("https://github.com/"):]
                repo_data = github_api.get_repo(repo_name.strip('/'))

                self.process_repository(github_api, repo_data)

                has_issues = repo_data.get('has_issues', False)

                if has_issues:
                    issues_counter['issues_enabled'] += 1
                else:
                    issues_counter['issues_disabled'] += 1

                repo.has_issues = has_issues
                repo.save()
            except Exception as e:
                print(e)
                print(f"Something went wrong, skipping this repo {repo}")
        print("Syncing issues done.")
        print(f"Found {issues_counter['issues_enabled']} repos with enabled issues")
        print(f"and {issues_counter['issues_disabled']} repos with disabled issues")
    def search_and_process_pocs(self, github_api, query, start_year=None, end_year=None, start_date_sync=None):
        """
        Recursively search for PoCs using refined queries to handle GitHub's
        1000-result limit. If results exceed 1000, the query is refined further.
        """

        start_date = f"2000-01-01"
        if start_date_sync:
            start_date = start_date_sync
        elif start_year:
            start_date = f"{start_year}-01-01"

        if not end_year:
            end_year = datetime.now().year

        github_searcher = GitHubSearcher(GITHUB_TOKEN)
        # Fetch search results from GitHub API
        print(f"Final start date: {start_date} - start_date_sync: {start_date_sync}")
        repos = github_searcher.search(query, start_date=start_date, end_date=f"{end_year}-12-31")
        # Process each repository in the response
        for repo_data in tqdm(repos):
            if repo_data.get("fork", False):
                continue
            # try:
            self.process_repository(github_api, repo_data)

        # if depth < 3 and depth<max_depth: # and page == 11 and
        #     for i in range(10):
        #         refined_query = f"{query}{i}"
        #         self.search_and_process_pocs(github_api, refined_query, depth + 1)




    def process_repository(self, github_api, repo_data):
        def process_text_for_cves(title, about_and_topics, readme):
            for item in [title, about_and_topics, readme]:
                cves = extract_cves(item)
                if cves: return cves
            return []

        repo_full_name = repo_data['full_name']
        repo_name = repo_data['name']
        github_id = repo_data['id']

        # Update fields only if the counts have increased
        current_stars_count = repo_data.get('stargazers_count', 0)
        current_forks_count = repo_data.get('forks_count', 0)
        # current_watchers_count = repo_data.get('subscribers_count', 0)

        similar_old_object = POC.objects.filter(github_id=github_id, stars_count=current_stars_count, forks_count=current_forks_count)
        if similar_old_object.exists():
            # Currently we're executing many queries for this, but it can be optimized
            return
        poc_about = repo_data.get('description', ' ')
        if not poc_about: poc_about = ' ' # Dunno why it's required, but am too busy to debug
        poc_topics = ' '.join(repo_data.get('topics', []))
        about_and_topics = poc_about + poc_topics
        poc_readme = github_api.get_readme_content(repo_full_name)

        possible_cve_ids = process_text_for_cves(repo_name, about_and_topics, poc_readme)
        if len(possible_cve_ids) > MAX_CVES_PER_REPO:
            self.stderr.write(
                f"Too many CVEs for repo: {repo_full_name}. Max is {MAX_CVES_PER_REPO} but {len(possible_cve_ids)} found for this repo.")
            return
        if not possible_cve_ids or len(possible_cve_ids) == 0:
                self.stderr.write(f"No CVE found for repo: {repo_full_name}")
                return
        try:
            poc = POC.objects.get(github_id=github_id)
            new_poc = False
        except POC.DoesNotExist:
            poc = POC.objects.create(
                name=repo_name,
                github_id=github_id,
                link=repo_data['html_url'],
                stars_count=repo_data.get('stargazers_count', 0),
                forks_count=repo_data.get('forks_count', 0),
                watch_count=repo_data.get('subscribers_count', 0),
                about=poc_about,
                repo_language=repo_data['language'],
                repo_size=repo_data['size'],
                repo_created_at=repo_data['created_at'],
                readme=github_api.get_readme_content(repo_full_name)
            )
            new_poc = True

        # Iterate over all possible CVE IDs and establish many-to-many relationships
        for cve_id in possible_cve_ids:
            cve, _ = CVE.objects.get_or_create(id=cve_id)
            # Create the mapping if it doesn't exist
            CVEPOCMapping.objects.get_or_create(cve_id=cve, poc_id=poc.id)

        update_fields = []

        # Check for stars increase
        if current_stars_count > 0 and (new_poc or current_stars_count > poc.stars_count):
            self.update_star_history(github_api, poc, repo_full_name)
            poc.stars_count = current_stars_count
            update_fields.append('stars_count')
        # Check for forks increase
        if current_forks_count > 0 and (new_poc or current_forks_count > poc.forks_count):
            self.update_fork_history(github_api, poc, repo_full_name)
            poc.forks_count = current_forks_count
            update_fields.append('forks_count')
        # Check for watchers increase
        # if current_watchers_count > 0 and (new_poc or current_watchers_count > poc.watch_count):
        #     self.update_watch_history(github_api, poc, repo_full_name)
        #     poc.watch_count = current_watchers_count
        #     update_fields.append('watch_count')

        # Update the readme, about fields
        if not poc_readme:
            poc_readme = github_api.get_readme_content(repo_full_name)
        poc.readme = poc_readme

        poc.about = poc_about
        update_fields.extend(['readme', 'about'])
        poc.save(update_fields=update_fields)


    @staticmethod
    def _new_event_times(existing_qs, time_field, event_times):
        """
        Return the timestamps from `event_times` that are not stored yet.

        No user identifiers are stored, so events can't be matched per user.
        Instead, keep only events newer than the latest stored one. Events that
        share the latest stored timestamp are skipped up to the number already
        stored at that exact time, so same-second events aren't lost or doubled.
        """
        latest = existing_qs.aggregate(latest=Max(time_field))["latest"]
        if latest is None:
            return list(event_times)
        already_at_latest = existing_qs.filter(**{time_field: latest}).count()
        new_times = []
        for ts in event_times:
            if ts > latest:
                new_times.append(ts)
            elif ts == latest:
                if already_at_latest > 0:
                    already_at_latest -= 1
                else:
                    new_times.append(ts)
        return new_times

    def update_star_history(self, github_api, poc, repo_full_name):
        time.sleep(1)
        stars = github_api.get_paginated_data(f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/stargazers")
        star_times = [parse_datetime(star["starred_at"]) for star in stars if star.get("starred_at")]
        new_times = self._new_event_times(Star.objects.filter(poc=poc), "starred_at", star_times)
        Star.objects.bulk_create([Star(poc=poc, starred_at=ts) for ts in new_times])

    def update_fork_history(self, github_api, poc, repo_full_name):
        time.sleep(1)
        forks = github_api.get_paginated_data(f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/forks")
        fork_times = [parse_datetime(fork["created_at"]) for fork in forks if fork.get("created_at")]
        new_times = self._new_event_times(Fork.objects.filter(poc=poc), "forked_at", fork_times)
        Fork.objects.bulk_create([Fork(poc=poc, forked_at=ts) for ts in new_times])

    def update_watch_history(self, github_api, poc, repo_full_name):
        # time.sleep(3)
        # GitHub gives no watch timestamp, so only add rows for the net increase in watchers.
        watchers = github_api.get_paginated_data(f"{GITHUB_API_BASE_URL}/repos/{repo_full_name}/subscribers")
        missing = len(watchers) - Watch.objects.filter(poc=poc).count()
        if missing > 0:
            now = timezone.now()
            Watch.objects.bulk_create([Watch(poc=poc, watched_at=now) for _ in range(missing)])
