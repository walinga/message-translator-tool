import json
import re
from operator import itemgetter
from collections import OrderedDict
from urllib.request import urlopen
from bs4 import BeautifulSoup

# Extracts the full text from the provided link
# Returns an array of words
def extract_text(link):
    html_doc = urlopen(link).read()
    soup = BeautifulSoup(html_doc, 'html.parser')
    
    full_text = []
    for raw_str in soup.body.stripped_strings:
        full_text.append(raw_str)

    full_text_str = ' '.join(full_text)

    pnum_map = OrderedDict()
    for pnum_div in soup.find_all("div", class_="pnum"):
        par = pnum_div.parent
        par_text = ' '.join(par.strings)
        raw_text_index = full_text_str.find(par_text)
        pnum_map[pnum_div.string] = len(full_text_str[:raw_text_index].split())

    return {
        'raw_text': full_text_str,
        'words_list': full_text_str.split(),
        'pnum_map': pnum_map
    }

def lambda_handler(event, context):
    message_id = event['messageId']
    quote = event['quote']
    if (len(message_id) > 15 or len(quote) > 100000):
        return {
            'statusCode': 400
        }

    english_link = "https://www.messagehub.info/en/readMessage.msg?ref_num=" + message_id
    spanish_link = "https://www.messagehub.info/es/readMessage.msg?ref_num=" + message_id

    english_data = extract_text(english_link)
    spanish_data = extract_text(spanish_link)

    english_text, raw_text, pnum_map = itemgetter('words_list', 'raw_text', 'pnum_map')(english_data)
    spanish_text, raw_text_es, pnum_map_es = itemgetter('words_list', 'raw_text', 'pnum_map')(spanish_data)

    # Determine best match using "Sliding window" algorithm
    #  -> tokenize text and quote into lists of words
    #  -> check each possible chunk of words (chunk size = len(quote))
    #  -> choose the chunk with the most matching words
    quote_len = len(quote.split())
    quote_words = set(quote.split())
    quote_index = -1
    max_score = 0
    for start_i in range(len(english_text) - quote_len):
        chunk = english_text[start_i : start_i + quote_len]

        # Compare number of matching words via set intersection
        chunk_words = set(chunk)
        score = len(quote_words & chunk_words)

        if score >= max_score:
            max_score = score
            quote_index = start_i

    quote_end_index = quote_index + quote_len
    best_match = ' '.join(english_text[quote_index:quote_end_index])
    print('[Best match]', best_match)

    # Determine start/end paragraph
    start_pnum = -1
    end_pnum = -1
    prev_index = -1
    for pnum, index in pnum_map.items():
        if quote_index >= prev_index and quote_index < index:
            start_pnum = prev_pnum
        if quote_end_index >= prev_index and quote_end_index < index:
            end_pnum = pnum
            break
        prev_pnum = pnum
        prev_index = index

    matched_quote = ' '.join(english_text[pnum_map[start_pnum]:pnum_map[end_pnum]])
    translation = ' '.join(spanish_text[pnum_map_es[start_pnum]:pnum_map_es[end_pnum]])
    print('[Matched quote]', matched_quote)
    print('[Full translation]', translation)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'quote': matched_quote,
            'matchIndex': matched_quote.find(best_match),
            'translation': translation,
            'source': spanish_link
        })
    }

# DEBUG
# if __name__ == "__main__":
#     resp = lambda_handler({
#         'messageId': '56-0527',
#         'quote': "So is it today.\n44People say, “Oh preacher, you're too narrow-minded. You'll take all the pleasures away from the church when you go to preaching against these kind of things and that kind of thing.” Brother, if the church stood where she professes to stand, she would love the things of God and hate the things of the world. Not our mixed multitude. That's what's the matter today: a mixed multitude; a people who desires the things of the world and wants to pity along with the church. That's what causes someone fall. That's what shuts off prayer meeting. That's the way ... organizes all kind of societies in the church and take out the altar off the front, and the only fire is just in the basement."
#         }, {})
    # print(resp)