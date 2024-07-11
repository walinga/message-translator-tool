import json
from urllib.request import urlopen
from bs4 import BeautifulSoup

def extract_text(link):
    html_doc = urlopen(link).read()
    soup = BeautifulSoup(html_doc, 'html.parser')
    return soup.get_text()

def lambda_handler(event, context):
    message_id = event['messageId']
    quote = event['quote']
    if (len(message_id) > 15 or len(quote) > 100000):
        return {
            'statusCode': 400
        }

    english_link = "https://www.messagehub.info/en/readMessage.msg?ref_num=" + message_id
    spanish_link = "https://www.messagehub.info/es/readMessage.msg?ref_num=" + message_id

    english_text = extract_text(english_link)
    spanish_text = extract_text(spanish_link)

    # print(english_text)
    print('[Spanish text]', spanish_text[:50])

    # TODO: Determine nearest paragraph number
    # TODO: More flexible text comparison
    #   - Implemnent "Sliding window" algorithm
    #    -> tokenize text and quote into lists of words
    #    -> Check each possible chunk of words (chunk size = len(quote))
    #    -> Choose the chunk with the most matching words in order

    index = english_text.find(quote)
    translation = spanish_text[index:index+len(quote)]

    print('[Full translation]', translation)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'translation': spanish_text[:50],
            'source': spanish_link
        })
    }

# Test only
# lambda_handler({
#     'messageId': '56-0527',
#     'quote': "People say, “Oh preacher, you're too narrow-minded. You'll take all the pleasures away from the church when you go to preaching against these kind of things and that kind of thing.” Brother, if the church stood where she professes to stand, she would love the things of God and hate the things of the world. Not our mixed multitude. That's what's the matter today: a mixed multitude; a people who desires the things of the world and wants to pity along with the church. That's what causes someone fall. That's what shuts off prayer meeting. That's the way ... organizes all kind of societies in the church and take out the altar off the front, and the only fire is just in the basement."
#     }, {})