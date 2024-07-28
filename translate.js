function handleSuccess(payload) {
    const body = JSON.parse(payload.body);
    console.log("body", body);
    console.log("source", body.source);

    document.getElementById('quote-box').style.display = 'block';
    document.getElementById('matched-quote').textContent = body.quote;
    document.getElementById('translated-quote').textContent = body.translation;
    document.getElementById('translation-source').textContent = body.source;
}

/**
 * Splits the quote input into the individual quotes and extracts the message IDs.
 * Returns a map of messageId -> quote
 */
function splitQuotes(quoteInput) {
    // TODO: Add helpful error message for CAB-03 messages
    const messageIdMatches = [...quoteInput.matchAll(/\d{2}\-\d{4}\w?/g), {index: quoteInput.length}];
    const quoteMap = new Map();
    for (let i = 0; i < messageIdMatches.length - 1; i++) {
        const data = messageIdMatches[i];
        const index = data.index;
        const endIndex = messageIdMatches[i+1].index;
        quoteMap.set(data[0], quoteInput.slice(index, endIndex));
    }
    return quoteMap;
}

function performTranslation(messageId, quote) {
    return translateQuote(messageId, quote)
        .then(payload => {
            // console.log("Response payload", payload);
            if (payload.statusCode === 200) {
                return handleSuccess(payload);
            }

            if (payload.error) {
                document.getElementById('error-text').textContent = payload.error;
            }
            throw new Error('An error occured while performing translation:' + JSON.stringify(payload));
        })
        // TODO: Extend error functionality for multiple quotes
        .catch(err => {
            console.log(err)
            document.getElementById('error-text').style.display = 'block'
        })
}

async function translateQuotes(messageIdInput, quoteInput) {
    const messageIdProvided = messageIdInput.replace(/\s/g, '') !== '';
    if (messageIdProvided && (!/^\w+\-\w+$/.test(messageIdInput) || messageIdInput.length > 15)) {
        alert('Invalid message identifier. Please use the format 50-0505M');
        return;
    }

    if (quoteInput.replace(/\s/g, '') === '') {
        alert('A quote must be entered');
        return;
    }

    const quoteMap = splitQuotes(quoteInput);
    console.log('quoteMap', quoteMap);

    // TODO: Double-check existing functionality (message ID + quote entered)
    if (quoteMap.size === 0 && !messageIdProvided) {
        alert('Could not extract message ID');
        return;
    }

    Promise.allSettled([...quoteMap.keys()].map(messageId =>
        performTranslation(messageId, quoteMap.get(messageId))
    )).then((results) => {
        results.forEach((result) => console.log(result.status))
    })
}

async function onTranslateClick() {
    document.getElementById('quote-box').style.display = 'none';
    document.getElementById('error-text').style.display = 'none'
    document.getElementById('loader').style.display = 'block';
    document.getElementById('error-text').textContent = 'An error occurred. Please try again later';

    const messageIdInput = document.getElementById('message-id-input').value;
    const quoteInput = document.getElementById('quote-input').value;
    await translateQuotes(messageIdInput, quoteInput);

    document.getElementById('loader').style.display = 'none'
}

window.onTranslateClick = onTranslateClick;