import json
import re
from operator import itemgetter
from collections import OrderedDict
from urllib.request import urlopen
from bs4 import BeautifulSoup

PAR_DELTA_BUFFER = 3

# Removes punctuation from the given string
def strip_punctuation(s):
    return re.sub(r'[^\w]','',s)

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
        key = int(pnum_div.string)
        pnum_map[key] = len(full_text_str[:raw_text_index].split())

    words_list = full_text_str.split()
    pnum_map[key+1] = len(words_list)

    return {
        'raw_text': full_text_str,
        'words_list': words_list,
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
    quote_words = quote.split()
    quote_len = len(quote_words)
    quote_words_set = set(quote_words)
    quote_index = -1
    max_score = 0
    for start_i in range(len(english_text) - quote_len):
        chunk = english_text[start_i : start_i + quote_len]
        chunk_words = set(chunk)

        # Compare number of matching words via set intersection
        score = len(quote_words_set & chunk_words)

        # Add an extra point if the first words match
        if strip_punctuation(quote_words[0]) == strip_punctuation(chunk[0]):
            score += 1

        if score >= max_score:
            max_score = score
            quote_index = start_i

    quote_end_index = quote_index + quote_len
    best_match = ' '.join(english_text[quote_index:quote_end_index])
    print('[Best match]', best_match)

    # Determine start/end paragraph
    start_pnum = 1
    end_pnum = -1
    prev_index = -1
    prev_pnum = -1
    for pnum, index in pnum_map.items():
        if quote_index >= index:
            start_pnum = pnum
        if quote_end_index >= index:
            end_pnum = pnum + 1
        prev_index = index
   
    start_delta_back = quote_index - pnum_map[start_pnum]
    start_delta_forward = pnum_map[start_pnum+1] - quote_index
    start_delta_buffer = 0 if start_delta_back <= 1 else PAR_DELTA_BUFFER
    if start_delta_back < start_delta_forward:
        spanish_quote_start = pnum_map_es[start_pnum] + start_delta_back - start_delta_buffer
    else:
        spanish_quote_start = pnum_map_es[start_pnum+1] - start_delta_forward - start_delta_buffer

    end_delta_back = pnum_map[end_pnum] - quote_end_index
    end_delta_forward = quote_end_index - pnum_map[end_pnum-1]
    end_delta_buffer = 0 if end_delta_forward <= 1 else PAR_DELTA_BUFFER
    if end_delta_back < end_delta_forward:
        spanish_quote_end = pnum_map_es[end_pnum] - end_delta_back + end_delta_buffer
    else:
        spanish_quote_end = pnum_map_es[end_pnum-1] + end_delta_forward + end_delta_buffer

    translation = ' '.join(spanish_text[spanish_quote_start:spanish_quote_end])
    print('[Full translation]', translation)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'quote': best_match,
            'translation': translation,
            'source': spanish_link,
            'paragraphNumber': start_pnum
        })
    }

# DEBUG
if __name__ == "__main__":
    # resp = lambda_handler({
    #     'messageId': '60-0515E',
    #     'quote': "There’s where the church is failing today, on that walk. Do you know that even your own behavior can knock somebody else out of getting healed? Your misbehavior, of unconfessed sins of you believers, can cause this church to bitterly fail. And at the Day of the Judgment you’ll be responsible for every bit of it. “Oh,” you say, “now, wait a minute, Brother Branham.” Well, that’s the Truth. Think of it!"
    #     }, {})
    # print(resp)

    q = "So is it today! People say, “Oh, preacher, you’re too narrow-minded. You take all the pleasures away from the church, when you go to preaching against these kind of things and that kind of thing.”"
    for w in q.split():
        print(strip_punctuation(w))