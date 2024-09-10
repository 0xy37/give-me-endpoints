# GiveMeEndpoints
Give Me Endpoints is a simple URL enumeration tool designed to extract endpoints and subdomains from HTML and JavaScript files. Built for penetration testers and bug bounty hunters.

The tool supports scanning single URLs, reading from a list of URLs, and provides output options for saving results in text and CSV formats. With improved regex parsing and domain filtering, it ensures only URLs from the same domain are analyzed.

<img src="https://github.com/user-attachments/assets/3ffd24b2-152c-480f-ae49-6af0bfbf2851" width="900" height="500">

## Features
- HTML & JavaScript parsing: Extracts URLs, endpoints, and paths from both HTML and JS files.
- Output Options: Save results as text or CSV for further analysis.
- Enhanced Regex: Utilizes an advanced regex parser for more accurate URL extraction.
- No external JS alerts: Only extracts and evaluates on-domain JavaScript files.
- Status Codes and Titles: Displays the status code and page title for each extracted endpoint.

## Installation
### Prerequisites

    Python 3.6+

Install the following libraries:

    pip install requests beautifulsoup4 colorama

## Clone the Repository



```
git clone https://github.com/0xy37/give-me-endpoints
cd give-me-endpoints
```

## Usage

Run the tool with either a single URL or a list of URLs in a file. Output the results in a text or CSV format.

### Basic Usage:

```
python3 gme.py -u https://example.com
```

### Scan from a List of URLs:
```
python3 gme.py -uL urls.txt
```

### Save Results to Text:
```
python3 gme.py -u https://example.com -oT results.txt
```

### Save Results to CSV:
```
python3 gme.py -u https://example.com -oC results.csv
```

### Print the status code and the HTML title:
```
python3 gme.py -u https://example.com -s -t
```

### Example Output

![Screenshot 2024-09-10 210223](https://github.com/user-attachments/assets/9d74693e-71d9-42b0-b3a0-9cbc4c0a55f3)


### Acknowledgments
GerbenJavado's LinkFinder for inspiration on regex parsing.
