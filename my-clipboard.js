function hideCopyPrompt() {
    document.getElementById('copied-prompt').style.display = 'none';
}

var clipboard = new ClipboardJS('#copy-translation');
clipboard.on('success', function(e) {
    document.getElementById('copied-prompt').style.display = 'block';
    setTimeout(hideCopyPrompt, 2000);
});
clipboard.on('error', function(e) {
    console.warn(e);
});
  