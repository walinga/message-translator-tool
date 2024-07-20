function handleSuccess(body) {
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

    if (!/^\w+\-\w+$/.test(messageId)) {
        alert('Invalid message identifier. Please use the format 50-0505M');
        return;
    }

    if (quote.replace(/\s/g, '') === '') {
        alert('A quote must be entered');
        return;
    }

    return translateQuote(messageId, quote)
        .then(body => handleSuccess(body))
        .catch(() => {
            document.getElementById('error-text').style.display = 'block'
        })
}

async function onTranslateClick() {
    document.getElementById('quote-box').style.display = 'none';
    document.getElementById('error-text').style.display = 'none'
    document.getElementById('loader').style.display = 'block';

    const messageId = document.getElementById('message-id-input').value;
    const quote = document.getElementById('quote-input').value;

    await performTranslation(messageId, quote);

    document.getElementById('loader').style.display = 'none'
}

window.onTranslateClick = onTranslateClick;