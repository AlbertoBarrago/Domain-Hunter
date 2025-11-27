# Domain Hunter

## What's This About?

It helps you find available domains and check their prices.
a little bit instable... WHOIS is not reliable.

## Requirements

- Python 3.x (the newer the better!)
- python-whois (for being nosey about domains)
- requests (for talking to the internet)
- A cup of coffee ☕ (script runs better with caffeine)
- Patience (it's thorough, like your grandma checking your homework)

## How to Install Dependencies 

`pip install -r requirements.txt`

## Environment
Create an account on WHOIS database provider and get your API key.
Rename file `.sample.env` to `.env` and fill in the required fields.

## How to Use 

1. Make sure you have all the requirements (see above)
2. Run the script: `python main.py`
3. Add the domains you want to check, a single one or a list in JSON format
    1. Example: `["example.com", "example2.com"]`
    2. Example: `["example.com"]`
4. Check the generated report (it'll be named something like `domain_analysis_20230615_123456.txt`)

## License 

This project is licensed under the "Do Whatever You Want Just Don't Blame Me" License.