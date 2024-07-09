import json
from urllib.request import urlopen
from bs4 import BeautifulSoup

def lambda_handler(event, context):
    link = "https://www.messagehub.info/en/readMessage.msg?ref_num=56-0527"

    html_doc = urlopen(link).read()
    # print(html_doc)

    soup = BeautifulSoup(html_doc, 'html.parser')
    text = soup.get_text()
    # print(text)

    # TODO: Text comparison

    print(text[:50])

    return {
        'statusCode': 200,
        'body': json.dumps(text[:50])
    }