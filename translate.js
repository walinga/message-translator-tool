function handleSuccess(payload, parNums) {
    const body = JSON.parse(payload.body);
    console.log("body", body);
    console.log("source", body.source);

    const endParNumText =
        parNums && parNums[0] !== parNums[1] ? '-' + parNums[1] : '';
    const parNumText =
        parNums
            ? ' (Paragraph ' + parNums[0] + endParNumText + ')'
            : '';
    const translationBox = document.getElementById('translated-quote');
    translationBox.textContent = translationBox.textContent.concat(body.messageInfo.spanishTitle, parNumText, '\r\n', body.translation, '\r\n\r\n');

    const sourceBox = document.getElementById('translation-source');
    if (!sourceBox.textContent.includes(body.source)) {
        sourceBox.textContent = sourceBox.textContent.concat(body.source, '\r\n');
    }
}

function handleError(messageId, payload) {
    const errorText = '(' + payload.error + ')' || '(An unknown error occured)';
    const quoteBox = document.getElementById('matched-quote');
    quoteBox.textContent = quoteBox.textContent.concat(messageId, '\r\n', errorText, '\r\n\r\n');
    const translationBox = document.getElementById('translated-quote');
    translationBox.textContent = translationBox.textContent.concat(messageId, '\r\n', errorText, '\r\n\r\n');
}

function isEmpty(s) {
    return s.replace(/\s/g, '') === '';
}

/**
 * Modifies quoteMap in-place to split a chunk into multiple paragraphs.
 */
function splitParagraphs(messageId, chunk, quoteMap) {
    const parNumMatches = [...chunk.matchAll(/\n(\d+) +(?=\w)/g)];
    if (parNumMatches.length === 0) {
        quoteMap.push([messageId, chunk]);
        return;
    }

    for (let i = 0; i < parNumMatches.length; i++) {
        const match = parNumMatches[i];
        let currentMatch = match;
        let endMatch = parNumMatches[i+1];
        // NOTE: Uncomment to enable sending multiple pars in one request
        // while (endMatch && Number(currentMatch[1]) + 1 === Number(endMatch[1])) {
        //     i++;
        //     currentMatch = endMatch;
        //     endMatch = parNumMatches[i+1];
        // }

        const startIndex = match.index + match[0].length;
        const endIndex = endMatch ? endMatch.index : chunk.length;
        const paragraph = chunk.slice(startIndex, endIndex);
        if (!isEmpty(paragraph)) {
            quoteMap.push([messageId, paragraph, [match[1], parNumMatches[i][1]]]);
        }
    }
}

/**
 * Splits the quote input into the individual quotes and extracts the message IDs.
 * Returns a map of messageId -> quote
 */
function splitQuotes(quoteInput) {
    const messageIdMatches = [...quoteInput.matchAll(/(\d{2}\-\d{4}\w?)|(\w{3}-\d{2})/g), {index: quoteInput.length}];
    const quoteMap = [];
    for (let i = 0; i < messageIdMatches.length - 1; i++) {
        const data = messageIdMatches[i];
        const index = data.index;
        const endIndex = messageIdMatches[i+1].index;
        const quote = quoteInput.slice(index, endIndex);
        splitParagraphs(data[0], quote, quoteMap)
    }
    return quoteMap;
}

function performTranslation(messageId, quote, parNums) {
    return translateQuote(messageId, quote)
        .then((payload) => {
            return { payload, messageId, parNums };
        })
}

function translateQuotes(quoteInput) {
    if (quoteInput.replace(/\s/g, '') === '') {
        alert('A quote must be entered');
        return;
    }

    const quoteMap = splitQuotes(quoteInput);
    console.log('quoteMap', quoteMap);

    if (quoteMap.size === 0) {
        alert('Could not extract message ID. Please start each quote with a message identifier such as 50-0505M');
        return;
    }

    return Promise.allSettled(quoteMap.map(([messageId, quote, parNums]) => {
        // console.log('quoteMap entry', messageId, quote, parNums)
        return performTranslation(messageId, quote, parNums)
    })).then((results) => {
        document.getElementById('quote-box').style.display = 'block';
        results.forEach((result) => {
            const payload = result.value.payload;
            const messageId = result.value.messageId;
            if (payload.statusCode === 200) {
                handleSuccess(payload, result.value.parNums);
            } else {
                handleError(messageId, payload);
            }
        })
        document.getElementById('copy-translation').setAttribute("data-clipboard-text", document.getElementById('translated-quote').textContent);
    })
    .catch(err => {
        console.log(err)
        document.getElementById('error-text').style.display = 'block'
    })
}

async function onTranslateClick() {
    document.getElementById('quote-box').style.display = 'none';
    document.getElementById('translated-quote').textContent = '';
    document.getElementById('translation-source').textContent = '';
    document.getElementById('error-text').style.display = 'none'
    document.getElementById('loader').style.display = 'block';
    document.getElementById('error-text').textContent = 'An error occurred. Please try again later';

    const quoteInput = document.getElementById('quote-input').value;
    await translateQuotes(quoteInput);

    document.getElementById('loader').style.display = 'none'
}

window.onTranslateClick = onTranslateClick;