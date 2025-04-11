import requests
import json
import logging
import sys
import re
import random
import asyncio
import tldextract
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, quote_plus, parse_qs, urlencode
from typing import Dict, List, Set, Optional
import time
import colorama
import argparse
from colorama import Fore, Style
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class URLExtractor:
    def __init__(self, target_domain: str):
        self.target_domain = self._normalize_domain(target_domain)
        self.found_urls: Set[str] = set()
        
        # Comprehensive URL patterns
        self.url_patterns = [
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]+',
            r'https?://[^\s<>"]+?[-\w+&@#/%=~|$?!:,.]*[-\w+&@#/%=~|$]',
            r'//(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]+',
            r'https?%3A%2F%2F(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]+'
        ]
        
        # Interesting file extensions
        self.interesting_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.csv', 
            '.zip', '.tar', '.gz', '.rar', '.bak', '.sql', '.conf',
            '.env', '.log', '.xml', '.json', '.yaml', '.yml'
        }

        # Known advertising and tracking domains to exclude
        self.excluded_domains = {
            'google.com', 'googleadservices.com', 'doubleclick.net',
            'facebook.com', 'fbcdn.net', 'twitter.com', 'googletagmanager.com',
            'analytics.google.com', 'ads.google.com', 'bing.com', 'duckduckgo.com'
        }

    def _normalize_domain(self, domain: str) -> str:
        """Normalize the target domain to ensure consistency."""
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        return domain

    def _is_valid_url(self, url: str) -> bool:
        """Check if the URL belongs to the target domain and is not excluded."""
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False
            
            if parsed.scheme not in {'http', 'https'}:
                return False

            # Extract domain and subdomain
            ext = tldextract.extract(parsed.netloc)
            url_domain = f"{ext.domain}.{ext.suffix}"
            if ext.subdomain:
                url_domain = f"{ext.subdomain}.{url_domain}"

            # Extract target domain and subdomain
            target_ext = tldextract.extract(self.target_domain)
            target_base = f"{target_ext.domain}.{target_ext.suffix}"
            if target_ext.subdomain:
                target_base = f"{target_ext.subdomain}.{target_base}"

            # Exclude known advertising and tracking domains
            if any(excluded_domain in url_domain for excluded_domain in self.excluded_domains):
                return False

            # Ensure the URL belongs to the target domain
            return url_domain.endswith(target_base)

        except Exception as e:
            logging.debug(f"URL validation error for {url}: {str(e)}")
            return False

    def _clean_url(self, url: str) -> str:
        """Clean the URL by removing tracking parameters and fragments."""
        url = url.strip()
        tracking_params = {'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid'}
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            filtered_params = {k: v for k, v in params.items() if k not in tracking_params}
            clean_query = urlencode(filtered_params, doseq=True)
            url = url.split('?')[0]
            if clean_query:
                url = f"{url}?{clean_query}"
        return url.split('#')[0]

    def extract_from_regex(self, content: str) -> Set[str]:
        """Extract URLs from raw text using regex patterns."""
        urls = set()
        for pattern in self.url_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                url = match.group(0)
                if url.startswith('//'):
                    url = f"https:{url}"
                if self._is_valid_url(url):
                    urls.add(self._clean_url(url))
        return urls

    def extract_from_html(self, content: str) -> Set[str]:
        """Extract URLs from Google search results HTML content."""
        urls = set()
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Google search results are typically inside <div class="g"> or <a> tags
            for result in soup.find_all('div', class_='g'):
                link = result.find('a', href=True)
                if link:
                    url = link['href']
                    
                    # Skip Google's tracking URLs (e.g., /url?q=)
                    if url.startswith('/url?q='):
                        url = url.split('/url?q=')[1].split('&')[0]
                    
                    # Decode URL-encoded characters
                    url = requests.utils.unquote(url)
                    
                    # Ensure the URL is valid and belongs to the target domain
                    if self._is_valid_url(url):
                        urls.add(self._clean_url(url))
            
            # Additional check for other potential result links
            for link in soup.find_all('a', href=True):
                url = link['href']
                if url.startswith('/url?q='):
                    url = url.split('/url?q=')[1].split('&')[0]
                url = requests.utils.unquote(url)
                if self._is_valid_url(url):
                    urls.add(self._clean_url(url))
                    
        except Exception as e:
            logging.error(f"HTML parsing error: {str(e)}")
        
        return urls

    def extract_urls(self, content: str, check_interesting: bool = True) -> Set[str]:
        """Extract and filter URLs from content."""
        try:
            urls = self.extract_from_regex(content)
            urls.update(self.extract_from_html(content))
            
            if check_interesting:
                interesting_urls = {
                    url for url in urls if any(url.lower().endswith(ext) for ext in self.interesting_extensions)
                }
                if interesting_urls:
                    logging.info(f"Found {len(interesting_urls)} potentially interesting URLs:")
                    for url in interesting_urls:
                        logging.info(f"Interesting URL found: {url}")
            
            return urls
            
        except Exception as e:
            logging.error(f"URL extraction error: {str(e)}")
            return set()
        
class DorkScanner:
    def __init__(self, 
                domain: str,
                config_file: str,
                output_path: str = "results",
                threads: int = 5,
                proxy_list: Optional[List[str]] = None,
                rate_limit: float = 1.0,
                timeout: int = 30,
                max_retries: int = 3):
        # Basic properties
        self.domain = domain
        self.config_file = config_file
        self.output_path = Path(output_path)
        self.threads = threads
        self.proxy_list = proxy_list or []
        self.current_proxy_index = 0
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries

        # User-Agent handling
        self.user_agents = self._load_user_agents()
        self.current_user_agent_index = 0

        # Requests session setup
        self.session = self._create_session()
        self.last_request_time = 0

        # Results storage
        self.results: Dict[str, List[Dict]] = {}

        # URL extractor for handling URLs
        self.url_extractor = URLExtractor(domain)

        # Search engines with customizable templates
        self.search_engines = {
            'google': 'https://www.google.com/search?q={}&num=100'
        }

        # Setup logging
        self.setup_logging()

    
    def _load_user_agents(self) -> List[str]:
        """Load a pool of User-Agents dynamically."""
        user_agent = UserAgent()
        user_agents = [
            user_agent.chrome,
            user_agent.firefox,
            user_agent.safari,
            user_agent.opera,
            user_agent.edge
        ]
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Loaded User-Agents: {user_agents}")
        return user_agents

    def get_next_user_agent(self) -> str:
        """Rotate through User-Agents in the pool."""
        user_agent = self.user_agents[self.current_user_agent_index]
        self.current_user_agent_index = (self.current_user_agent_index + 1) % len(self.user_agents)
        return user_agent

    def _create_session(self) -> requests.Session:
        """Create and configure a requests.Session with retry logic."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update({
            'User-Agent': self.get_next_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        return session


    def setup_logging(self) -> None:
        """Set up logging configuration."""
        self.output_path.mkdir(parents=True, exist_ok=True)
        log_file = self.output_path / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def get_next_proxy(self) -> Optional[str]:
        """Get the next proxy from the proxy list."""
        if not self.proxy_list:
            return None
        
        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        return proxy

    def save_results(self, category: str, results: List[Dict]) -> None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save JSON results
        json_file = self.output_path / f"scan_results_{timestamp}.json"
        try:
            with open(json_file, 'w') as f:
                json.dump({category: results}, f, indent=4)
            print(f"{Fore.GREEN}✓ Results saved to:{Style.RESET_ALL} {json_file}")
        except Exception as e:
            logging.error(f"Error saving JSON results: {str(e)}")

        # Generate HTML report
        html_file = self.output_path / f"scan_report_{timestamp}.html"
        try:
            html_content = self._generate_html_report(category, results)
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"{Fore.GREEN}✓ HTML report generated:{Style.RESET_ALL} {html_file}")
        except Exception as e:
            logging.error(f"Error generating HTML report: {str(e)}")

    def _generate_html_report(self, category: str, results: List[Dict]) -> str:
        """Generate an HTML report from the scan results."""
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Dork Scanner Report - {self.domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .success {{ color: #28a745; }}
                .error {{ color: #dc3545; }}
                .dork-result {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .urls-found {{ margin-left: 20px; list-style-type: none; padding: 0; }}
                .urls-found li {{ margin: 5px 0; }}
                .urls-found a {{ color: #007bff; text-decoration: none; }}
                .urls-found a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Dork Scanner Report</h1>
                <p><strong>Domain:</strong> {self.domain}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Category:</strong> {category}</p>
            </div>
        """
        
        for result in results:
            status_class = 'success' if result['status'] == 'success' else 'error'
            html_template += f"""
            <div class="dork-result">
                <h3>Dork: {result['dork']}</h3>
                <p class="{status_class}">Status: {result['status']}</p>
            """
            
            if result['status'] == 'success':
                html_template += f"""
                <p>URLs Found ({len(result['urls_found'])}):</p>
                <ul class="urls-found">
                """
                for url in result['urls_found']:
                    html_template += f"<li><a href='{url}' target='_blank' rel='noopener noreferrer'>{url}</a></li>"
                html_template += "</ul>"
            elif 'error' in result:
                html_template += f"<p class='error'>Error: {result['error']}</p>"
            
            html_template += "</div>"
        
        html_template += """
        </body>
        </html>
        """
        return html_template

    async def process_dork(self, dork: str, category: str) -> Dict:
        """Process each dork and dynamically rotate User-Agents."""
        try:
            formatted_dork = dork.replace("{subdomain}", self.domain)
            print(f"{Fore.YELLOW}Processing dork:{Style.RESET_ALL} {formatted_dork}")

            for engine, url_template in self.search_engines.items():
                try:
                    # Update the session with the next User-Agent
                    user_agent = self.get_next_user_agent()
                    self.session.headers.update({'User-Agent': user_agent})
                    print(f"{Fore.CYAN}Using User-Agent:{Style.RESET_ALL} {user_agent}")

                    # Make the request
                    search_url = url_template.format(quote_plus(formatted_dork))
                    response = self.session.get(search_url, timeout=self.timeout)

                    if response.status_code == 200:
                        if "captcha" in response.text.lower():
                            logging.warning(f"{engine} returned CAPTCHA, trying next engine...")
                            continue

                        urls = self.url_extractor.extract_urls(response.text)
                        print(f"{Fore.GREEN}✓ Found {len(urls)} URLs from {engine}{Style.RESET_ALL}")
                        return {
                            "dork": formatted_dork,
                            "engine": engine,
                            "status": "success",
                            "urls_found": list(urls),
                            "count": len(urls)
                        }

                except requests.exceptions.RequestException as e:
                    logging.warning(f"Error with {engine}: {str(e)}")
                    continue

                await asyncio.sleep(self.rate_limit)

            return {
                "dork": formatted_dork,
                "status": "error",
                "error": "All search engines failed or returned CAPTCHAs",
                "urls_found": []
            }

        except Exception as e:
            logging.error(f"Unexpected error processing dork: {str(e)}")
            return {
                "dork": formatted_dork,
                "status": "error",
                "error": str(e),
                "urls_found": []
            }

    async def scan(self) -> None:
        """Main scanning method that processes all dorks asynchronously."""
        self.print_banner()
        dorks = self.load_dorks()
        
        for category, dork_list in dorks.items():
            print(f"\n{Fore.CYAN}[+] Processing category:{Style.RESET_ALL} {category}")
            category_results = []
            
            # Create tasks for all dorks in the category
            tasks = []
            for dork in dork_list:
                tasks.append(self.process_dork(dork, category))
            
            # Process dorks concurrently with rate limiting
            try:
                results = await asyncio.gather(*tasks)
                category_results.extend(results)
                
                # Print category summary
                successful_scans = sum(1 for r in results if r['status'] == 'success')
                total_urls = sum(len(r['urls_found']) for r in results if r['status'] == 'success')
                print(f"\n{Fore.GREEN}Category Summary:{Style.RESET_ALL}")
                print(f"├─ Successful scans: {successful_scans}/{len(tasks)}")
                print(f"└─ Total URLs found: {total_urls}")
                
                # Save results for this category
                self.save_results(category, category_results)
                
            except Exception as e:
                logging.error(f"Error processing category {category}: {str(e)}")
                continue
            
            # Small delay between categories
            await asyncio.sleep(2)
        
        print(f"\n{Fore.GREEN}Scan completed!{Style.RESET_ALL}")
    
    def print_banner(self):
        """Print the scanner banner with basic information."""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║        Enhanced Security Dork Scanner       ║
╚══════════════════════════════════════════╝{Style.RESET_ALL}
        
{Fore.GREEN}Target Domain:{Style.RESET_ALL} {self.domain}
{Fore.GREEN}Start Time:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Fore.GREEN}Output Directory:{Style.RESET_ALL} {self.output_path}
{Fore.GREEN}Threads:{Style.RESET_ALL} {self.threads}
{Fore.GREEN}Rate Limit:{Style.RESET_ALL} {self.rate_limit} seconds
"""
        print(banner)

    def load_dorks(self) -> Dict:
        """Load and validate dorks from the configuration file."""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            if 'security_dorks' not in config:
                raise ValueError("Configuration file must contain 'security_dorks' key")
                
            dorks = config['security_dorks']
            if not isinstance(dorks, dict):
                raise ValueError("'security_dorks' must be a dictionary of categories")
                
            # Validate dork format
            for category, dork_list in dorks.items():
                if not isinstance(dork_list, list):
                    raise ValueError(f"Category '{category}' must contain a list of dorks")
                
            logging.info(f"Loaded {len(dorks)} dork categories")
            return dorks
            
        except FileNotFoundError:
            logging.error(f"Dorks file {self.config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON in {self.config_file}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading dorks: {str(e)}")
            sys.exit(1)

async def main():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(description="Enhanced Security Dork Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-o", "--output", default="results",
                        help="Output directory for results")
    parser.add_argument("-c", "--config", default="security_dorks.json",
                        help="Path to the dorks configuration file")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Number of concurrent threads")
    parser.add_argument("-r", "--rate-limit", type=float, default=1.0,
                        help="Rate limit between requests in seconds")
    parser.add_argument("-T", "--timeout", type=int, default=30,
                        help="Request timeout in seconds")
    parser.add_argument("-R", "--retries", type=int, default=3,
                        help="Maximum number of retries for failed requests")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., socks5://127.0.0.1:9050)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()

    # Configure logging level based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger().setLevel(log_level)

    try:
        scanner = DorkScanner(
            domain=args.domain,
            config_file=args.config,
            output_path=args.output,
            threads=args.threads,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
            max_retries=args.retries
        )
        await scanner.scan()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())