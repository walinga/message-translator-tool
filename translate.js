function handleSuccess(payload) {
    const body = JSON.parse(payload.body);
    console.log("body", body);
    console.log("source", body.source);

    document.getElementById('quote-box').style.display = 'block';
    document.getElementById('matched-quote').textContent = body.quote;
    document.getElementById('translated-quote').textContent = body.translation;
    document.getElementById('translation-source').textContent = body.source;
}

function performTranslation(messageId, quote) {
    if (messageId.replace(/\s/g, '') === '') {
        alert('A message identifier must be entered');
        return;
    }

    if (!/^\w+\-\w+$/.test(messageId) || messageId.length > 15) {
        alert('Invalid message identifier. Please use the format 50-0505M');
        return;
    }

    if (quote.replace(/\s/g, '') === '') {
        alert('A quote must be entered');
        return;
    }

    return translateQuote(messageId, quote)
        .then(payload => {
            console.log("Response payload", payload);
            if (payload.statusCode === 200) {
                return handleSuccess(payload);
            }

            if (payload.error) {
                document.getElementById('error-text').textContent = payload.error;
            }
            throw new Error('An error occured while performing translation:' + JSON.stringify(payload));
        })
        .catch(err => {
            console.log(err)
            document.getElementById('error-text').style.display = 'block'
        })
}

async function onTranslateClick() {
    document.getElementById('quote-box').style.display = 'none';
    document.getElementById('error-text').style.display = 'none'
    document.getElementById('loader').style.display = 'block';
    document.getElementById('error-text').textContent = 'An error occurred. Please try again later';

    const messageId = document.getElementById('message-id-input').value;
    const quote = document.getElementById('quote-input').value;

    await performTranslation(messageId, quote);

    document.getElementById('loader').style.display = 'none'
}

window.onTranslateClick = onTranslateClick;