var DUMMY_EL = document.createElement("p");
/** @type {HTMLElement} **/
let editTargetEl = DUMMY_EL;

var editControls = document.createElement("div");
editControls.setAttribute("id", "edit-controls");

var editToggleItalic = document.createElement("button");
editToggleItalic
    .setAttribute("title", "toggle italicization of selected text");
editToggleItalic.style.setProperty("font-style", "italic");
editToggleItalic.insertBefore(document.createTextNode("I"), null);

var editToggleBold = document.createElement("button");
editToggleBold
    .setAttribute("title", "toggle bolding of selected text");
editToggleBold.style.setProperty("font-weight", "bold");
editToggleBold.insertBefore(document.createTextNode("B"), null);

var editToggleUnderline = document.createElement("button");
editToggleUnderline
    .setAttribute("title", "toggle underlining of selected text");
editToggleUnderline.style.setProperty("text-decoration", "underline");
editToggleUnderline.insertBefore(document.createTextNode("U"), null);

var editToggleStrikethrough = document.createElement("button");
editToggleStrikethrough
    .setAttribute("title", "toggle strike-through of selected text");
editToggleStrikethrough.insertBefore(document.createTextNode("S"), null);
editToggleStrikethrough.style.setProperty("text-decoration", "line-through");

var editSwaptWithElBefore = document.createElement("button");
editSwaptWithElBefore.setAttribute("title", "move up");
editSwaptWithElBefore.innerHTML = "&uarr;";

var editSwaptWithElAfter = document.createElement("button");
editSwaptWithElAfter.setAttribute("title", "move down");
editSwaptWithElAfter.innerHTML = "&darr;";

var editDelete = document.createElement("button");
editDelete.setAttribute("title", "delete");
editDelete.innerHTML = "&times;";

var editAddHeading1After = document.createElement("button");
editAddHeading1After
    .setAttribute("title", "insert primary section heading below");
editAddHeading1After
    .insertBefore(document.createTextNode("+ Heading 1." ), null);

var editAddParagraphAfter = document.createElement("button");
editAddParagraphAfter.setAttribute("title", "insert paragraph below");
editAddParagraphAfter
    .insertBefore(document.createTextNode("+ Paragraph"  ), null);

var editAddImageAfter = document.createElement("button");
editAddImageAfter.setAttribute("title", "upload and insert image below");
editAddImageAfter
    .insertBefore(document.createTextNode("+ Image"), null);

editControls.insertBefore(editToggleItalic       , null);
editControls.insertBefore(editToggleBold         , null);
editControls.insertBefore(editToggleUnderline    , null);
editControls.insertBefore(editToggleStrikethrough, null);
editControls.insertBefore(editSwaptWithElBefore  , null);
editControls.insertBefore(editSwaptWithElAfter   , null);
editControls.insertBefore(editDelete             , null);
editControls.insertBefore(editAddHeading1After   , null);
editControls.insertBefore(editAddParagraphAfter  , null);
editControls.insertBefore(editAddImageAfter      , null);

var fileUploadInputEl = document.createElement("INPUT");
fileUploadInputEl.style.setProperty("visibility", "hidden");
fileUploadInputEl.setAttribute("type", "file");
editControls.insertBefore(fileUploadInputEl, null);

/** @returns {boolean} **/
function ensureEditing() {
    if (editTargetEl === DUMMY_EL) {
        if (!document.body) { return false; }
        if (!document.body.firstElementChild || (
            document.body.firstElementChild.nodeName !== "H1" &&
            document.body.firstElementChild.nodeName !== "P"  &&
            document.body.firstElementChild.nodeName !== "IMG"
        )) {
            editTargetEl = document.createElement("H1");
            editTargetEl.insertBefore(
                document.createTextNode("Heading 1."), null);
            document.body.insertBefore(editTargetEl, null);
        } else {
            editTargetEl = document.body.firstElementChild;
        }
    }
    editTargetEl.setAttribute("contenteditable", "");
    editTargetEl.focus();
    editTargetEl.parentNode
        .insertBefore(editControls, editTargetEl.nextElementSibling);
    return true;
}

/** @param {Event} event **/
function handleClick(event) {
    if (!event.target) { return; }
    if (event.target.nodeName === "H1" ||
        event.target.nodeName === "P"  ||
        event.target.nodeName === "IMG"
    ) {
        editTargetEl.removeAttribute("contenteditable");
        editTargetEl = event.target;
        ensureEditing();
        return;
    }

    var eventTargetIsControl =
        event.target.compareDocumentPosition(editControls)
        & Node.DOCUMENT_POSITION_CONTAINS;
    if (!eventTargetIsControl) { return; }
    if (!ensureEditing()) {
        console.log(`'ensureEditing()' failed!`);
        return;
    }
    if (event.type === "touchstart") { return; }

    event.preventDefault();
    event.stopPropagation();

    if (event.target === editToggleItalic)
        { document.execCommand("italic"       , false, null); return; }
    if (event.target === editToggleBold)
        { document.execCommand("bold"         , false, null); return; }
    if (event.target === editToggleUnderline)
        { document.execCommand("underline"    , false, null); return; }
    if (event.target === editToggleStrikethrough)
        { document.execCommand("strikethrough", false, null); return; }

    if (event.target === editSwaptWithElBefore) {
        editTargetEl.removeAttribute("contenteditable");
        var elBefore = editTargetEl.previousElementSibling;
        if (!elBefore) { return; }
        editTargetEl.parentNode.insertBefore(editTargetEl, elBefore);
        ensureEditing();
        return;
    }
    if (event.target === editSwaptWithElAfter) {
        editTargetEl.removeAttribute("contenteditable");
        var elAfter = editTargetEl.nextElementSibling;
        if (elAfter === editControls)
            { elAfter = elAfter.nextElementSibling; }
        if (!elAfter) { return; }
        editTargetEl.parentNode
            .insertBefore(editTargetEl, elAfter.nextElementSibling);
        ensureEditing();
        return;
    }
    if (event.target === editDelete) {
        var elAfter = editTargetEl.nextElementSibling;
        if (elAfter === editControls)
            { elAfter = elAfter.nextElementSibling; }
        editTargetEl.parentNode.removeChild(editTargetEl);
        editTargetEl = elAfter || DUMMY_EL;
        ensureEditing();
        return;
    }

    if (event.target === editAddHeading1After) {
        editTargetEl.removeAttribute("contenteditable");
        var elAfter = editTargetEl.nextElementSibling;
        if (elAfter === editControls)
            { elAfter = elAfter.nextElementSibling; }
        var parentNode = editTargetEl.parentNode;
        editTargetEl = document.createElement("H1");
        editTargetEl.insertBefore(document.createTextNode("Heading 1."), null);
        parentNode.insertBefore(editTargetEl, elAfter);
        ensureEditing();
        return;
    }
    if (event.target === editAddParagraphAfter) {
        editTargetEl.removeAttribute("contenteditable");
        var elAfter = editTargetEl.nextElementSibling;
        if (elAfter === editControls)
            { elAfter = elAfter.nextElementSibling; }
        var parentNode = editTargetEl.parentNode;
        editTargetEl = document.createElement("P");
        editTargetEl.insertBefore(document.createTextNode("Paragraph"), null);
        parentNode.insertBefore(editTargetEl, elAfter);
        ensureEditing();
        return;
    }
    if (event.target === editAddImageAfter) {
        editTargetEl.removeAttribute("contenteditable");
        var elAfter = editTargetEl.nextElementSibling;
        if (elAfter === editControls)
            { elAfter = elAfter.nextElementSibling; }
        var parentNode = editTargetEl.parentNode;
        fileUploadInputEl.setAttribute("accept", "image/*");
        fileUploadInputEl.click();
        return;
    }
}

function handleFileUpload() {
    var files = this.files;
    if (!files || !files.length) { return; }
    var elAfter = editTargetEl.nextElementSibling;
    if (elAfter === editControls)
        { elAfter = elAfter.nextElementSibling; }
    var parentNode = editTargetEl.parentNode;
    for (var i = 0; i < files.length; ++i) {
        /** @type {File} **/
        var file = files[i];
        var ft = file.type;
        if (ft.length >= 6 &&
            ft[0] === 'i' && ft[1] === 'm' && ft[2] === 'a' &&
            ft[3] === 'g' && ft[4] === 'e' && ft[5] === '/'
        ) {
            editTargetEl = document.createElement("img");
            editTargetEl.src = URL.createObjectURL(file);
            parentNode.insertBefore(editTargetEl, elAfter);
        }
    }
    files.length = 0;
    ensureEditing();
}

window.addEventListener("load"            , ensureEditing);
window.addEventListener("DOMContentLoaded", ensureEditing);
window.addEventListener("touchstart", handleClick);
window.addEventListener("mousedown" , handleClick);
fileUploadInputEl.addEventListener("change", handleFileUpload);

