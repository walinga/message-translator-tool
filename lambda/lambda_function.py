import json
import re
from operator import itemgetter
from collections import OrderedDict
from urllib.request import urlopen
from bs4 import BeautifulSoup

PAR_DELTA_BUFFER = 3
DEBUG = False

# Removes punctuation from the given string
def strip_punctuation(s):
    return re.sub(r'[^\w]','',s)

# Splits a string on whitespace and another punctuation-like characters
# Some characters common within words are NOT included, such as:
# - U+0027 : APOSTROPHE
# - U+002D : HYPHEN-MINUS
# - U+2019 : RIGHT SINGLE QUOTATION MARK
def split_string(s):
    return list(filter(None, re.split(r'[\s!"#$&\(\*\+,\.\/:;<=>?¡¢“”…]+', s)))

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
        pnum_map[key] = len(split_string(full_text_str[:raw_text_index]))

    words_list = split_string(full_text_str)
    pnum_map[key+1] = len(words_list)

    word_index_map = OrderedDict()
    cursor = 0
    for index, word in enumerate(words_list):
        pos = full_text_str[cursor:].index(word)
        word_index_map[index] = pos + cursor
        cursor += pos + len(word)
    word_index_map[len(words_list)] = len(full_text_str)

    return {
        'raw_text': full_text_str,
        'words_list': words_list,
        'pnum_map': pnum_map,
        'word_index_map': word_index_map
    }

def determine_quote_boundary(quote_index, pnum_map, pnum_map_es, prev_pnum):
    delta_back = quote_index - pnum_map[prev_pnum]
    delta_forward = pnum_map[prev_pnum+1] - quote_index
    delta_buffer = 0 if delta_back <= 1 else PAR_DELTA_BUFFER
    if delta_back < delta_forward:
        es_boundary = pnum_map_es[prev_pnum] + delta_back
    else:
        es_boundary = pnum_map_es[prev_pnum+1] - delta_forward
    return {
        'es_boundary': es_boundary,
        'delta_buffer': delta_buffer
    }

def determine_translation(quote, english_data, spanish_data):
    english_word_list, english_text, pnum_map, word_index_map = itemgetter('words_list', 'raw_text', 'pnum_map', 'word_index_map')(english_data)
    spanish_word_list, spanish_text, pnum_map_es, word_index_map_es = itemgetter('words_list', 'raw_text', 'pnum_map', 'word_index_map')(spanish_data)

    # Determine best match using "Sliding window" algorithm
    #  -> tokenize text and quote into lists of words
    #  -> check each possible chunk of words (chunk size = len(quote))
    #  -> choose the chunk with the most matching words
    trimmed_words = list(map(strip_punctuation, english_word_list))
    quote_words = list(map(strip_punctuation, split_string(quote)))
    quote_len = len(quote_words)
    quote_words_set = set(quote_words)
    quote_index = -1
    max_score = 0
    for start_i in range(len(english_word_list) - quote_len):
        chunk = trimmed_words[start_i : start_i + quote_len]
        chunk_words = set(chunk)

        # Compare number of matching words via set intersection
        score = len(quote_words_set & chunk_words)

        # Add an extra point if the first words match
        if quote_words[0] == chunk[0]:
            score += 1

        if score >= max_score:
            max_score = score
            quote_index = start_i

    quote_end_index = quote_index + quote_len
    best_match = english_text[word_index_map[quote_index] : word_index_map[quote_end_index]]
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
   
    # TODO: As the start delta, use the greater of 3 words previous OR start of sentence
    start_boundary_data = determine_quote_boundary(quote_index, pnum_map, pnum_map_es, start_pnum)
    spanish_quote_start = start_boundary_data['es_boundary'] - start_boundary_data['delta_buffer']

    end_boundary_data = determine_quote_boundary(quote_end_index, pnum_map, pnum_map_es, end_pnum - 1)
    spanish_quote_end = end_boundary_data['es_boundary'] + end_boundary_data['delta_buffer']

    translation = spanish_text[word_index_map_es[spanish_quote_start] : word_index_map_es[spanish_quote_end]]
    print('[Full translation]', translation)

    return {
        'quote': best_match,
        'translation': translation,
        'paragraphNumber': start_pnum
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

    translation_data = determine_translation(quote, english_data, spanish_data)
    translation_data['source'] = spanish_link

    return {
        'statusCode': 200,
        'body': json.dumps(translation_data)
    }

# DEBUG
if __name__ == "__main__":
    DEBUG = True

    # resp = lambda_handler({
    #     'messageId': '61-1015E',
    #     'quote': "Over in Ecclesiastes, the 12th chapter and the 13th verse, it’s written like this, see. Let us hear the conclusion of the whole matter: Fear God, and keep his commandments: for this is the full duty of man. The conclusion of the whole matter is to “fear God.” And, when, you cannot have respects until you have fear. You’ve got to have fear of God. Solomon said also, in the Proverbs, that: The fear of God is the beginning of wisdom: The fear of God is the beginning of wisdom: Now, that don’t mean that you’re afraid of Him, but that means that you are giving Him “respects” and “reverence.” And when you respect God, you fear God. You fear that you might displease Him in some way, you fear lest you would do something wrong. You wouldn’t want to. I fear my mother. I fear my—my wife. I fear my church. I fear all of God’s servants, unless I should put a stumbling block somewhere in their way. I—I fear the people. I fear the people of the city, unless I should do something wrong that would cause them to think that I wasn’t a Christian. See, you’ve got, before you can have respects, you’ve got to have fear. And God demands it, He demands respects. God does, He demands it. And fear brings it. And we know that fear brings respects."
    #     }, {})
    # print(resp)

    print(len(split_string("Let every unclean spirit that's in these people, every spirit of doubting, every spirit of fear, every denominational cling, every habit, every sickness, every disease that's among the people, leave; in the name of Jesus Christ may it come out of this group of people. And may they be free from this hour on, that they can eat the eagle food that we're believing You'll send us through the week, Lord, breaking open those Seals and showing us those mysteries that's been hid since the foundation of the world, as You promised. They are Yours, Father. In the name of Jesus Christ. Amen.")))
    print(len(split_string("Permite que todo espíritu inmundo que está en estas personas, todo espíritu de duda, todo espíritu de temor, toda atadura denominacional, toda mala costumbre, toda enfermedad, toda dolencia que esté entre la gente, que se vaya. En el Nombre de Jesucristo, que eso salga de este grupo de personas. Y que ellos sean libres desde esta hora en adelante, para que ellos puedan comer el Alimento de Águila que estamos creyendo que Tú nos enviarás a través de la semana, Señor; abriendo esos Sellos y mostrándonos esos misterios que han sido escondidos desde la fundación del mundo, como Tú has prometido. Ellos son Tuyos, Padre. En el Nombre de Jesucristo. Amén.")))

    q = """
    """
    # print(len(q.split()))
    # print(split_string(q))
    # for w in q.split():
    #     print(strip_punctuation(w))
    for i in split_string(q):
        if re.sub(r'[^\w\-\'’\[\]]','',i) != i:
            print(i)