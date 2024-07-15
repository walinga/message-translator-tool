function handleSuccess(body) {
    document.getElementById('quote-box').style.display = 'block';
    document.getElementById('matched-quote').textContent = body.quote;
    document.getElementById('translated-quote').textContent = body.translation;
    document.getElementById('translation-source').textContent = body.source;
}

function onTranslateClick() {
    document.getElementById('quote-box').style.display = 'none';
    document.getElementById('error-text').style.display = 'none'
    document.getElementById('loader').style.display = 'block';

    const messageId = document.getElementById('message-id-input').value;
    const quote = document.getElementById('quote-input').value;
    
    console.log('[messageId]', messageId);
    console.log('[quote]', quote);

    if (messageId.replace(/\s/g, '') === '') {
        alert('A message identifier must be entered');
        return;
    }

    // TODO: Regex to check messageId format (Tip: include CAB-03 and 50-0505M)

    if (quote.replace(/\s/g, '') === '') {
        alert('A quote must be entered');
        return;
    }
    translateQuote(messageId, quote)
        .then(body => handleSuccess(body))
        .catch(() => {
            document.getElementById('error-text').style.display = 'block'
        })
        .finally(() => {
            document.getElementById('loader').style.display = 'none'
        })
}

window.onTranslateClick = onTranslateClick;