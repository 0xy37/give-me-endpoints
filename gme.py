import argparse
import requests
from bs4 import BeautifulSoup
import re
import csv
import warnings
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from urllib3.exceptions import InsecureRequestWarning
from requests import RequestsDependencyWarning
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama
init(autoreset=True)

# Suppress warnings
warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning)  # For BeautifulSoup warnings

# ASCII Art for the tool name
def print_ascii_art():
    ascii_art = r"""
 ____ _____     _______   __  __ _____   _____ _   _  ____  ____  ___ ___ _   _ _____ ____ 
|___ |_ _\ \   / |____ | |  \/  |____ | |____ | | / |/ _  |/ _  |/ _ |_ _| | / |_   _|___ \
 _  | | | \ \ / /  |_  | | |\/| | |_  |   |_  | |/  | | | | (_| | | | | || |/  | | | / ___/
| |_| | |  \ V /  ___| | | |  | |___| |  ___| |  /| | |_| |\__  | |_| | ||  /| | | || (___ 
|____|___|  \_/  |_____| |_|  |_|_____| |_____|_/ |_|\____|   |_|\___|___|_/ |_| |_| \____|                                                                                           
               Extracting Endpoints and Paths from HTML/JS Files v.1 - By Yara AlHumaidan
    """
    print(Fore.MAGENTA + ascii_art + Style.RESET_ALL)


# Updated regex pattern for URL extraction
regex_str = r"""
    (?:"|')                              # Start newline delimiter
    (
        ((?:[a-zA-Z]{1,10}://|//)         # Match a scheme [a-Z]*1-10 or protocol
        [^"'/]{1,}\.                      # Match a domain name (any character except quotes, slashes, and domain)
        [a-zA-Z]{2,}[^"']{0,})            # The domain extension and path
        |
        (/[^"'><,;| *()(%%$^/\\\[\]]{1,}) # Relative URL
        |
        ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action))  # Filename with a path
        |
        ([a-zA-Z0-9_\-]{1,}/[a-zA-Z0-9_\-]{3,}/?)  # /dir/
        |
        ([a-zA-Z0-9_\-]{3,}/[a-zA-Z0-9_\-]{3,}/?)  # /dir/file
    )
    (?:"|')                               # End newline delimiter
"""

# Compile the regex pattern
regex = re.compile(regex_str, re.VERBOSE)

# Function to fetch content of a URL with retries
def fetch_content(url, headers):
    """Fetches the content of a URL."""
    headers = headers.copy()  # Create a copy of headers to avoid modifying the original
    headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')  # Default User-Agent
    try:
        response = requests.get(url, timeout=10, verify=False, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"{Fore.RED}Error fetching {url}: {e}")
        return None

# Function to extract URLs from HTML or JavaScript content using regex

def extract_endpoints(content, base_url):
    """Extracts endpoints from content using regex."""
    matches = re.findall(regex, content)
    results = set([urljoin(base_url, match[0]) for match in matches if match[0]])
    return list(results)

# Function to ensure only URLs from the same domain are processed

def filter_same_domain(urls, base_domain):
    """Filters URLs to include only those from the same domain."""
    return [url for url in urls if base_domain in urlparse(url).netloc]


# Function to show http status color coded
def get_status_colored(status_code):
    if status_code < 300:
        return f"{Fore.GREEN}{status_code}"  # OK responses are green
    elif status_code < 400:
        return f"{Fore.BLUE}{status_code}"  # Redirection responses are green
    elif status_code < 500:
        return f"{Fore.YELLOW}{status_code}"  # Client errors are yellow
    else:
        return f"{Fore.RED}{status_code}"  # Server errors are red


# Function to evaluate URLs (fetch status code and title) 

def evaluate_url(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'lxml')  # Use 'lxml' for parsing
        title = soup.title.string if soup.title else 'No Title'
        status_code = response.status_code
        print("[",get_status_colored(status_code),"]",f"{Fore.CYAN}URL: {url}",f"{Fore.YELLOW}Title: {title}")
        return (url, status_code, title)
    except requests.RequestException:
        print(f"{Fore.CYAN}URL: {url} {Fore.RED}Status: Failed to connect {Fore.YELLOW}Title: No Title")
        return (url, 'Failed to connect', 'No Title')

# Function to process URLs concurrently
def evaluate_urls_concurrently(urls):
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(evaluate_url, urls))
    return results

# Function to write results to text file
def write_to_text(results, file_name):
    """Writes results to a text file."""
    with open(file_name, 'w') as f:
        for result in results:
            f.write(f"{result[0]} - Status: {result[1]} - Title: {result[2]}\n")

# Function to write results to CSV file
def write_to_csv(results, file_name):
    """Writes results to a CSV file."""
    with open(file_name, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Status Code', 'Title'])
        writer.writerows(results)

def filter_js_files(js_files, base_url):
    """Filters JavaScript files to include only those from the same domain."""
    base_domain = urlparse(base_url).netloc
    return [js_file for js_file in js_files if urlparse(js_file).netloc == base_domain]

def main():
    
    print_ascii_art()  # Print the ASCII art
    
    parser = argparse.ArgumentParser(description="Give Me Endpoints (gme)")
    parser.add_argument("-u", "--url", help="Target URL", required=False)
    parser.add_argument("-uL", "--urllist", help="File containing list of URLs", required=False)
    parser.add_argument("-oT", "--output-text", help="Output results to text file", required=False)
    parser.add_argument("-oC", "--output-csv", help="Output results to CSV file", required=False)
    parser.add_argument("-s", "--status", action="store_true", help="Print status code")
    parser.add_argument("-t", "--title", action="store_true", help="Print HTML title")
    parser.add_argument("-H", "--header", help="Add specific header (e.g., 'Cookie: value')", required=False)

    args = parser.parse_args()

    headers = {}
    if args.header:
        header_key, header_value = args.header.split(':', 1)
        headers[header_key.strip()] = header_value.strip()

    urls = []

    if args.url:
        urls.append(args.url)
    if args.urllist:
        try:
            with open(args.urllist, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}File {args.urllist} not found.")
            return

    if not urls:
        print(f"{Fore.RED}At least one URL or URL file (-u or -uL) is required.")
        return

    all_results = []
    visited_urls = set()  # To store unique results
    for url in urls:
        base_domain = urlparse(url).netloc
        print(f"{Fore.CYAN}Fetching {url}...")
        html = fetch_content(url, headers)
        if not html:
            continue

        # Extract and evaluate endpoints and paths using enhanced regex
        endpoints = extract_endpoints(html, url)
        same_domain_endpoints = filter_same_domain(endpoints, base_domain)
        all_results.extend(evaluate_urls_concurrently(same_domain_endpoints))

        # Extract and evaluate JavaScript files related to the domain
        js_files = list(set([urljoin(url, script['src']) for script in BeautifulSoup(html, 'lxml').find_all('script') if script.get('src')]))
        js_files = filter_js_files(js_files, url)

        for js_file in js_files:
            if js_file in visited_urls:
                continue
            visited_urls.add(js_file)

            print(f"{Fore.CYAN}Fetching JavaScript file {js_file}...")
            js_content = fetch_content(js_file, headers)
            if not js_content:
                continue

            js_endpoints = extract_endpoints(js_content, url)
            same_domain_js_endpoints = filter_same_domain(js_endpoints, base_domain)
            all_results.extend(evaluate_urls_concurrently(same_domain_js_endpoints))
    
    # Output results to files if requested
    if args.output_text:
        write_to_text(all_results, args.output_text)
        print(f"{Fore.GREEN}Results written to {args.output_text}")

    if args.output_csv:
        write_to_csv(all_results, args.output_csv)
        print(f"{Fore.GREEN}Results written to {args.output_csv}")

if __name__ == "__main__":
    main()
