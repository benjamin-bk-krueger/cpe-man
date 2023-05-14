/*
    Get the content of an HTML element and copies it over to the clipboard.
    Should be compatible to all currently used and up-to-date browsers.
 */
function CopyToClipboard(id) {
    let textToCopy = document.getElementById(id).innerText;
    if(navigator.clipboard) {
        navigator.clipboard.writeText(textToCopy).then(() => {
            alert('Value copied to clipboard')
        })
    } else {
        console.log('Browser not compatible')
    }
}
