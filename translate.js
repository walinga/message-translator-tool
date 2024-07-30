function handleSuccess(payload) {
    const body = JSON.parse(payload.body);
    console.log("body", body);
    console.log("source", body.source);

    const quoteBox = document.getElementById('matched-quote');
    quoteBox.textContent = quoteBox.textContent.concat(body.messageInfo.englishTitle, '\r\n', body.quote, '\r\n\r\n');
    const translationBox = document.getElementById('translated-quote');
    translationBox.textContent = translationBox.textContent.concat(body.messageInfo.spanishTitle, '\r\n', body.translation, '\r\n\r\n');
    const sourceBox = document.getElementById('translation-source');
    sourceBox.textContent = sourceBox.textContent.concat(body.source, '\r\n');
}

function handleError(messageId, payload) {
    const errorText = '(' + payload.error + ')' || '(An unknown error occured)';
    const quoteBox = document.getElementById('matched-quote');
    quoteBox.textContent = quoteBox.textContent.concat(messageId, '\r\n', errorText, '\r\n\r\n');
    const translationBox = document.getElementById('translated-quote');
    translationBox.textContent = translationBox.textContent.concat(messageId, '\r\n', errorText, '\r\n\r\n');
}

/**
 * Splits the quote input into the individual quotes and extracts the message IDs.
 * Returns a map of messageId -> quote
 */
function splitQuotes(quoteInput) {
    const messageIdMatches = [...quoteInput.matchAll(/(\d{2}\-\d{4}\w?)|(\w{3}-\d{2})/g), {index: quoteInput.length}];
    const quoteMap = new Map();
    for (let i = 0; i < messageIdMatches.length - 1; i++) {
        const data = messageIdMatches[i];
        const index = data.index;
        const endIndex = messageIdMatches[i+1].index;
        const chunk = quoteInput.slice(index, endIndex);
        // Adjust the start of the quote to remove the paragraph number
        const parNumMatch = chunk.match(/(?<=\s\d+)\s/);
        const quote = parNumMatch && parNumMatch.index - index < 100
            ? chunk.slice(parNumMatch.index)
            : chunk;
        quoteMap.set(data[0], quote);
    }
    return quoteMap;
}

function performTranslation(messageId, quote) {
    return translateQuote(messageId, quote)
        .then((payload) => {
            return { payload, messageId };
        })
        .catch(err => {
            console.log(err)
            document.getElementById('error-text').style.display = 'block'
        })
}

function translateQuotes(messageIdInput, quoteInput) {
    if (quoteInput.replace(/\s/g, '') === '') {
        alert('A quote must be entered');
        return;
    }

    const quoteMap = splitQuotes(quoteInput);
    console.log('quoteMap', quoteMap);

    // If no message ID could be extracted, fallback to the message ID input
    if (quoteMap.size === 0) {
        if (messageIdInput.replace(/\s/g, '') === '') {
            alert('Could not extract message ID. Try entering a message ID');
            return;
        }

        if (!/^\w+\-\w+$/.test(messageIdInput) || messageIdInput.length > 15) {
            alert('Invalid message identifier. Please use the format 50-0505M');
            return;
        }

        quoteMap.set(messageIdInput, quoteInput);
    }

    return Promise.allSettled([...quoteMap.keys()].map(messageId =>
        performTranslation(messageId, quoteMap.get(messageId))
    )).then((results) => {
        document.getElementById('quote-box').style.display = 'block';
        results.forEach((result) => {
            const payload = result.value.payload;
            const messageId = result.value.messageId;
            if (payload.statusCode === 200) {
                handleSuccess(payload);
            } else {
                handleError(messageId, payload);
            }
        })
    })
}

async function onTranslateClick() {
    document.getElementById('quote-box').style.display = 'none';
    document.getElementById('matched-quote').textContent = '';
    document.getElementById('translated-quote').textContent = '';
    document.getElementById('translation-source').textContent = '';
    document.getElementById('error-text').style.display = 'none'
    document.getElementById('loader').style.display = 'block';
    document.getElementById('error-text').textContent = 'An error occurred. Please try again later';

    const messageIdInput = document.getElementById('message-id-input').value;
    const quoteInput = document.getElementById('quote-input').value;
    await translateQuotes(messageIdInput, quoteInput);

    document.getElementById('loader').style.display = 'none'
}

window.onTranslateClick = onTranslateClick;