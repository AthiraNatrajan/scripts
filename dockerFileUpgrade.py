import re
import requests
import json
import argparse

DOCKER_HUB_BASE_URL = "https://hub.docker.com/v2/repositories/library"

class DockerInsights:
    def __init__(self, docker_file_path):
        self.docker_file_path = docker_file_path
        self.image_name = None
        self.image_tag = None

    def extract_base_image_details(self):
        try:
            with open(self.docker_file_path, 'r') as file:
                for line in file:
                    if line.startswith("FROM"):
                        self._parse_from_line(line)
                        return self.image_name, self.image_tag
                print("Error: No FROM line found in Dockerfile.")
                return None, None
        except FileNotFoundError:
            print(f"Error: Dockerfile '{self.docker_file_path}' not found.")
            return None, None
        except IOError as e:
            print(f"Error reading Dockerfile: {e}")
            return None, None

    def _parse_from_line(self, line):
        try:
            line = line.strip()
            _, image_full = line.split(maxsplit=1)

            if ":" in image_full:
                self.image_name, self.image_tag = image_full.split(":", 1)
            else:
                self.image_name = image_full
                self.image_tag = "latest"

            self.image_name = self.image_name.strip()
            self.image_tag = self.image_tag.strip()

            print(f"Parsed Image Name: '{self.image_name}', Image Tag: '{self.image_tag}'")
        except ValueError:
            print("Error: Malformed FROM line in Dockerfile.")
            self.image_name, self.image_tag = None, None

    @staticmethod
    def fetch_image_tags(repo_name, tag_name=None):
        """Fetches all tags for a given repository and retrieves details for the specific tag."""
        tags_url = f"{DOCKER_HUB_BASE_URL}/{repo_name}/tags"
        params = {
            "page_size": 100,
            "ordering": "-last_updated",
            "name": tag_name
        }
        
        try:
            response = requests.get(tags_url, params=params)
            response.raise_for_status()
            tags_data = response.json()
            return tags_data.get("results", [])
        except requests.RequestException as e:
            print(f"Error fetching tags: {e}")
            return None

    @staticmethod
    def fetch_digest_details(repo_name, tag_name):
        """Fetches details about a specific tag, including the digest."""
        tags = DockerInsights.fetch_image_tags(repo_name, tag_name)
        if not tags:
            print("No tags found or error occurred.")
            return None

        for tag in tags:
            if tag["name"] == tag_name:
                # Tag found; now return the digest and other details
                digest_info = {
                    "tag": tag["name"],
                    "digest": tag["images"][0]["digest"],
                    "architecture": tag["images"][0]["architecture"],
                    "os": tag["images"][0]["os"]
                }
                return digest_info

        print("Specified tag not found.")
        return None

    @staticmethod
    def fetch_image_summaries(sha, repo):
        print("Fetching image summaries for ", sha)
        api_url = "https://api.dso.docker.com/v1/graphql"
        headers = {
            "Content-Type": "application/json",
        }

        query = """
        query imageSummariesByDigest($v1: Context!, $v2: [String!]!, $v3: ScRepositoryInput) {
            imageSummariesByDigest(context: $v1, digests: $v2, repository: $v3) {
                digest
                sbomState
                vulnerabilityReport {
                    critical
                    high
                    medium
                    low
                    unspecified
                    total
                }
            }
        }
        """

        variables = {
            "v1": {},
            "v2": [sha],
            "v3": {"hostName": "hub.docker.com", "repoName": repo},
        }

        response = requests.post(
            api_url, json={"query": query, "variables": variables}, headers=headers
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.status_code, "message": response.text}

    def get_vulnerabilities(self, image_name=None, image_tag=None):
        """Scan the image for vulnerabilities using Trivy."""
        digest_details = self.fetch_digest_details(image_name, image_tag)

        if digest_details:
            print("Digest Details:", digest_details)
            vulnerability_report = self.fetch_image_summaries(digest_details["digest"], image_name)
            if vulnerability_report:
                print("Vulnerability Report:", json.dumps(vulnerability_report, indent=4))
            else:
                print("No vulnerability report found.")
        else:
            print("Could not retrieve digest details.")

    def extract_tag_component(self, tag_name):
        match = re.search(r'(?<=\d-)(.*)', tag_name)
        return match.group(1) if match else None
    
    def extract_version(self, tag):
        """
        Extracts the version number, handling cases where the patch number might be missing.
        Returns the version as a string, e.g., '11.0' or '11.0.10'.
        """
        pattern = r'(\d+(?:\.\d+)?(?:\.\d+)?(?:\.\d+)?(?:_\d+)?|(?:\d+u\d+))'
    
        match = re.search(pattern, tag)
        if match:
            return match.group(0)
        else:
            print(f"Warning: Could not extract version from tag '{tag}'.")
            return None

    def compare_versions(self, version1, version2):
        """
        Compare two version strings. Returns True if version1 > version2.
        Allows comparison of versions with or without a patch segment.
        """
        v1_parts = list(map(int, version1.split('.')))
        v2_parts = list(map(int, version2.split('.')))
        
        # Pad shorter version lists with zeros for comparison
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)
        
        return v1_parts > v2_parts

    def get_available_upgrades(self):
        if self.image_name is None or self.image_tag is None:
            print("Error: Image name or tag not set. Please extract base image details first.")
            return []

        try:
            namespace = "library"
            image_name = self.image_name.lower()
            full_image_name = f"{namespace}/{image_name}"

            tag_filter = self.extract_tag_component(self.image_tag)
            tags_url = f"https://hub.docker.com/v2/repositories/library/{image_name}/tags?page_size=100&ordering=-name&name={tag_filter}"
            tags_response = requests.get(tags_url)
            tags_response.raise_for_status()

            available_tags = [result['name'] for result in tags_response.json()['results']]
            current_version = self.extract_version(self.image_tag)
            if current_version is None:
                print("Could not extract current version from the tag.")
                return []

            upgrades = []
            for tag in available_tags:
                tag_version = self.extract_version(tag)
                if tag_version and self.compare_versions(tag_version, current_version):
                    upgrades.append(tag)
            print(f"Available upgrades for '{full_image_name}:{self.image_tag}': {upgrades}")
            return upgrades

        except requests.exceptions.HTTPError as e:
            print(f"Error connecting to Docker Hub: {e}")
            return []
        except Exception as e:
            print(f"An error occurred while retrieving available upgrades: {e}")
            return []

    def is_minor_upgrade(self, current_tag, upgrade_tag):
        """
        Determines if upgrade_tag is a minor version upgrade from current_tag.
        """
        current_version = self.extract_version(current_tag)
        upgrade_version = self.extract_version(upgrade_tag)

        if current_version and upgrade_version:
            current_major, current_minor, *_ = map(int, current_version.split('.'))
            upgrade_major, upgrade_minor, *_ = map(int, upgrade_version.split('.'))

            return (current_major == upgrade_major and upgrade_minor > current_minor)

        return False

    def is_major_upgrade(self, current_tag, upgrade_tag):
        """
        Determines if upgrade_tag is a major version upgrade from current_tag.
        """
        current_version = self.extract_version(current_tag)
        upgrade_version = self.extract_version(upgrade_tag)

        if current_version and upgrade_version:
            current_major = int(current_version.split('.')[0])
            upgrade_major = int(upgrade_version.split('.')[0])

            return upgrade_major > current_major

        return False

    def is_patch_upgrade(self, current_tag, upgrade_tag):
        """
        Determines if upgrade_tag is a patch version upgrade from current_tag.
        """
        current_version = self.extract_version(current_tag)
        upgrade_version = self.extract_version(upgrade_tag)

        if current_version and upgrade_version:
            current_major, current_minor, current_patch = self._parse_version(current_version)
            upgrade_major, upgrade_minor, upgrade_patch = self._parse_version(upgrade_version)

            return (
                current_major == upgrade_major and 
                current_minor == upgrade_minor and 
                upgrade_patch > current_patch
            )

        return False

    def _parse_version(self, version_str):
        """Helper to parse a version string into major, minor, and patch with defaults if missing."""
        parts = version_str.split('.')
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return major, minor, patch
    
    def calculate_confidence_factor(self, current_risk_card, upgrade_risk_card):
        # Calculate total current risk
        total_current_risk = sum(current_risk_card)
        
        # Calculate total risk reduction
        total_risk_reduction = sum(max(current - upgrade, 0) for current, upgrade in zip(current_risk_card, upgrade_risk_card))
        
        # Calculate confidence factor
        if total_current_risk > 0:
            confidence_factor = (total_risk_reduction / total_current_risk) * 100
        else:
            confidence_factor = 0  # If there is no current risk, confidence is 0%

        return confidence_factor

    def classify_confidence(self, confidence_factor):
        if confidence_factor >= 75:
            return "High"
        elif confidence_factor >= 40:
            return "Medium"
        else:
            return "Low"
        
    def get_best_confidence_classification(self, classifications):
        # Define a mapping of classification to its ranking value
        classification_ranking = {
            "High": 3,
            "Medium": 2,
            "Low": 1
        }
        
        best_classification_value = 0
        best_classification = None
        
        # Loop through the classifications
        for classification in classifications:
            current_classification_value = classification_ranking.get(classification, 0)
            
            # Check if this classification is better than the best found so far
            if current_classification_value > best_classification_value:
                best_classification_value = current_classification_value
                best_classification = classification

        return best_classification
    
    def recommended_upgrades(self):
        """Iterate over available upgrades and get vulnerability reports to recommend the best upgrade."""
        if self.image_name is None or self.image_tag is None:
            print("Error: Image name or tag not set. Please extract base image details first.")
            return None

        # Fetch vulnerabilities for the current image
        current_digest_details = self.fetch_digest_details(self.image_name, self.image_tag)
        current_vulnerability_report = self.fetch_image_summaries(current_digest_details["digest"], self.image_name)

        if current_vulnerability_report is None:
            print("Error: No vulnerability report found for the current image.")
            return None

        current_image_summaries = current_vulnerability_report.get('data', {}).get('imageSummariesByDigest')
        if not current_image_summaries:
            print("Error: No image summaries found in the current image vulnerability report.")
            return None

        current_severity_scores = current_image_summaries[0].get('vulnerabilityReport')
        if current_severity_scores is None:
            print("Error: No severity scores found for the current image.")
            return None

        # Calculate the current image's total severity score and vulnerability count
        current_total_severity_score = (
            5 * current_severity_scores.get('critical', 0) + 
            4 * current_severity_scores.get('high', 0) +
            3 * current_severity_scores.get('medium', 0) + 
            2 * current_severity_scores.get('low', 0)
        )
        current_total_vulnerabilities = sum(current_severity_scores.values())
        current_risk_card = list(current_severity_scores.values())[:5]
        # Initialize recommendations
        recommended_major_upgrade = None
        recommended_minor_upgrade = None
        recommended_patch_upgrade = None
        recommended_minor_risk_card = []
        recommended_major_risk_card = []
        recommended_patch_risk_card = []
        best_major_severity_score = float('inf')
        best_minor_severity_score = float('inf')
        best_patch_severity_score = float('inf')
        best_major_vulnerability_count = float('inf')
        best_minor_vulnerability_count = float('inf')
        best_patch_vulnerability_count = float('inf')

        all_upgrade_details = []

        for upgrade in self.get_available_upgrades():
            print(f"Checking vulnerabilities for upgrade: {upgrade}")

            # Fetch digest details for the upgrade
            digest_details = self.fetch_digest_details(self.image_name, upgrade)
            if digest_details:
                # Fetch vulnerability report
                vulnerability_report = self.fetch_image_summaries(digest_details["digest"], self.image_name)

                if vulnerability_report is None:
                    print(f"Warning: No vulnerability report found for upgrade {upgrade}. Skipping...")
                    continue
                
                image_summaries = vulnerability_report.get('data', {}).get('imageSummariesByDigest')
                if not image_summaries:
                    print(f"Warning: No image summaries found in vulnerability report for upgrade {upgrade}. Skipping...")
                    continue
                
                severity_scores = image_summaries[0].get('vulnerabilityReport')
                if severity_scores is None:
                    print(f"Warning: No severity scores found for upgrade {upgrade}. Skipping...")
                    continue

                total_severity_score = (
                    5 * severity_scores.get('critical', 0) + 
                    4 * severity_scores.get('high', 0) +
                    3 * severity_scores.get('medium', 0) + 
                    2 * severity_scores.get('low', 0)
                )
                total_vulnerabilities = sum(severity_scores.values())

                print(f"image: {self.image_name}, severity_scores: {severity_scores}, Upgrade: {upgrade}, Severity Score: {total_severity_score}, Vulnerabilities: {total_vulnerabilities} , risk_card: {list(severity_scores.values())}")

                # Compare the upgrade with the current image vulnerabilities and severity scores
                if total_severity_score < current_total_severity_score and total_vulnerabilities < current_total_vulnerabilities:
                    # Collect details for the current upgrade
                    all_upgrade_details.append([
                        self.image_name,     # Image Name
                        upgrade,             # Upgrade Tag
                        total_severity_score,  # Severity Score
                        total_vulnerabilities,  # Total Vulnerabilities
                        severity_scores       # Severity Breakdown
                    ])

                    # Check for major upgrade recommendation
                    if self.is_major_upgrade(self.image_tag, upgrade):
                        # Always recommend if better in terms of severity and vulnerabilities
                        if (total_severity_score < best_major_severity_score or
                            (total_severity_score == best_major_severity_score and 
                            total_vulnerabilities < best_major_vulnerability_count)):
                            best_major_severity_score = total_severity_score
                            best_major_vulnerability_count = total_vulnerabilities
                            recommended_major_upgrade = upgrade
                            recommended_major_risk_card = list(severity_scores.values())[:5]

                    # Check for minor upgrade recommendation
                    elif self.is_minor_upgrade(self.image_tag, upgrade):
                        if (total_severity_score < best_minor_severity_score or
                            (total_severity_score == best_minor_severity_score and 
                            total_vulnerabilities < best_minor_vulnerability_count)):
                            best_minor_severity_score = total_severity_score
                            best_minor_vulnerability_count = total_vulnerabilities
                            recommended_minor_upgrade = upgrade
                            recommended_minor_risk_card = list(severity_scores.values())[:5]
                        
                    # Check for patch upgrade recommendation
                    elif self.is_patch_upgrade(self.image_tag, upgrade):
                        if (total_severity_score < best_patch_severity_score or
                            (total_severity_score == best_patch_severity_score and 
                            total_vulnerabilities < best_patch_vulnerability_count)):
                            best_patch_severity_score = total_severity_score
                            best_patch_vulnerability_count = total_vulnerabilities
                            recommended_patch_upgrade = upgrade
                            recommended_patch_risk_card = list(severity_scores.values())[:5]

        upgrade_final = []
        # Output the recommended upgrades
        if recommended_major_upgrade:
            print(f"Recommended major upgrade: {recommended_major_upgrade} with severity score: {best_major_severity_score} and vulnerabilities: {best_major_vulnerability_count}")
            upgrade_final.append([
                        self.image_name,     # Image Name
                        recommended_major_upgrade,             # Upgrade Tag
                        best_major_severity_score,  # Severity Score
                        best_major_vulnerability_count,  # Total Vulnerabilities
                        "MAJOR"
                    ])
        else:
            print("No suitable major upgrades found.")

        if recommended_minor_upgrade:
            print(f"Recommended minor upgrade: {recommended_minor_upgrade} with severity score: {best_minor_severity_score} and vulnerabilities: {best_minor_vulnerability_count}")
            upgrade_final.append([
                        self.image_name,     # Image Name
                        recommended_minor_upgrade,             # Upgrade Tag
                        best_minor_severity_score,  # Severity Score
                        best_minor_vulnerability_count,  # Total Vulnerabilities
                        "MINOR"
                    ])
        else:
            print("No suitable minor upgrades found.")

        if recommended_patch_upgrade:
            print(f"Recommended patch upgrade: {recommended_patch_upgrade} with severity score: {best_patch_severity_score} and vulnerabilities: {best_patch_vulnerability_count}")
            upgrade_final.append([
                        self.image_name,     # Image Name
                        recommended_patch_upgrade,             # Upgrade Tag
                        best_patch_severity_score,  # Severity Score
                        best_patch_vulnerability_count,  # Total Vulnerabilities
                        "PATCH"
                    ])
        else:
            print("No suitable patch upgrades found.")

        final_output = {}
        if (recommended_major_upgrade or recommended_minor_upgrade or recommended_patch_upgrade):
            current_severity_score = current_total_severity_score
            recommended_severity_scores = {
                "major": best_major_severity_score,
                "minor": best_minor_severity_score,
                "patch": best_patch_severity_score,
            }
            
            # Calculate how much severity has been reduced
            savings_risk = {}
            for key, value in recommended_severity_scores.items():
                if value is not None:
                    reduction = (current_severity_score - value) / current_severity_score * 100
                    savings_risk[key] = reduction if reduction > 0 else 0
                else:
                    savings_risk[key] = 0  # No upgrade, no savings

            confident_factor_major = self.calculate_confidence_factor(current_risk_card, recommended_major_risk_card)
            confident_factor_minor = self.calculate_confidence_factor(current_risk_card, recommended_minor_risk_card)
            confident_factor_patch = self.calculate_confidence_factor(current_risk_card, recommended_patch_risk_card)
            confident_factor = [self.classify_confidence(confident_factor_major), self.classify_confidence(confident_factor_minor), self.classify_confidence(confident_factor_patch)]
 
            # Prepare the final JSON structure
            pull_requests = []
            i = 0
            if recommended_major_upgrade:
                i += 1
                pull_requests.append({
                    "name": f"PR{i}",
                    "risk_card": [recommended_major_risk_card[j] - current_risk_card[j] for j in range(len(recommended_major_risk_card))],  # You might want to adjust this
                    "changes": [{
                        "package": self.image_name,  # You may want to specify the actual package if available
                        "current_version": self.image_tag,
                        "upgrade_version": recommended_major_upgrade,
                        "risk_card_current": current_risk_card,  # Adjust as necessary
                        "risk_card_upgrade": recommended_major_risk_card,
                        "Savings (risk)": f"reduce risk by {savings_risk['major']}%",
                        "Confidence Factor" : self.classify_confidence(confident_factor_major)
                    }]
                })
            
            if recommended_minor_upgrade:
                i += 1
                pull_requests.append({
                    "name": f"PR{i}",
                    "risk_card": [recommended_minor_risk_card[j] - current_risk_card[j] for j in range(len(recommended_minor_risk_card))],
                    "changes": [{
                        "package": self.image_name,
                        "current_version": self.image_tag,
                        "upgrade_version": recommended_minor_upgrade,
                        "risk_card_current": current_risk_card,
                        "risk_card_upgrade": recommended_minor_risk_card,
                        "Savings (risk)": f"reduce risk by {savings_risk['minor']}%",
                        "Confidence Factor" : self.classify_confidence(confident_factor_minor)
                    }]
                })
            
            if recommended_patch_upgrade:
                i += 1
                pull_requests.append({
                    "name": f"PR{i}",
                    "risk_card": [recommended_patch_risk_card[j] - current_risk_card[j] for j in range(len(recommended_patch_risk_card))],
                    "changes": [{
                        "package": self.image_name,
                        "current_version": self.image_tag,
                        "upgrade_version": recommended_patch_upgrade,
                        "risk_card_current": current_risk_card,
                        "risk_card_upgrade": recommended_patch_risk_card,
                        "Savings (risk)": f"reduce risk by {savings_risk['patch']}%",
                        "Confidence Factor" : self.classify_confidence(confident_factor_patch)
                    }]
                })

            summary = {
                "Number of PRs": len(pull_requests),
                "Confident_Factor": self.get_best_confidence_classification(confident_factor),
                "Savings (risk)": max(list(savings_risk.values())),
                "risk_card": current_risk_card
            }

            # Combine the summary and pull requests into the final JSON
            final_output = {
                "summary": summary,
                "pull_requests": pull_requests
            }

        # Save the final JSON to a file
        json_file_path = '/Users/athiran/Documents/dockerUpgrade/recommended_upgrades_summary.json'
        with open(json_file_path, 'w') as json_file:
            json.dump(final_output, json_file, indent=4)

        print(f"Summary saved to {json_file_path}")

        return recommended_major_upgrade, recommended_minor_upgrade, recommended_patch_upgrade

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Analyze Docker images for vulnerabilities and upgrades.')
    parser.add_argument('docker_file_path', type=str, help='Path to the Dockerfile')

    args = parser.parse_args()

    # Initialize DockerInsights with Dockerfile path
    docker_insights = DockerInsights(args.docker_file_path)

    # Extract base image details
    image_name, image_tag = docker_insights.extract_base_image_details()

    print("Image Name:", image_name)
    print("Image Tag:", image_tag)

    recommended_upgrade = docker_insights.recommended_upgrades()
    print("Best Recommended Upgrade:", recommended_upgrade)
