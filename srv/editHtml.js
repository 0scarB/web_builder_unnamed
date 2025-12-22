var       TIMES_UTF16_CODE_POINT =  215;
var  LEFT_ARROW_UTF16_CODE_POINT = 8592;
var    UP_ARROW_UTF16_CODE_POINT = 8593;
var RIGHT_ARROW_UTF16_CODE_POINT = 8594;
var  DOWN_ARROW_UTF16_CODE_POINT = 8595;

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
editSwaptWithElBefore.insertBefore(
    document.createTextNode(
        String.fromCodePoint(UP_ARROW_UTF16_CODE_POINT)), null);

var editSwaptWithElAfter = document.createElement("button");
editSwaptWithElAfter.setAttribute("title", "move down");
editSwaptWithElAfter.insertBefore(
    document.createTextNode(
        String.fromCodePoint(DOWN_ARROW_UTF16_CODE_POINT)), null);

var editDelete = document.createElement("button");
editDelete.setAttribute("title", "delete");
editDelete.insertBefore(
    document.createTextNode(
        String.fromCodePoint(TIMES_UTF16_CODE_POINT)), null);

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

var fileUploadInputEl = document.createElement("input");
fileUploadInputEl.style.setProperty("visibility", "hidden");
fileUploadInputEl.setAttribute("type", "file");
editControls.insertBefore(fileUploadInputEl, null);
var xmlSerializer = new XMLSerializer();

var fileTreeEl      = document.createElement("div");
var fileTreeHeading = document.createElement("h2");
fileTreeHeading.insertBefore(document.createTextNode("Files"), null);
fileTreeEl     .insertBefore(fileTreeHeading, null);
fileTreeEl.setAttribute("id", "file-tree");

/** @param   {string     } name
 *  @returns {HTMLElement} **/
function newFileTreeNodeEl(name) {
    var fileTreeNodeEl = document.createElement("li");

    var rowEl = document.createElement("div");

    var nameEl = document.createElement("input");
    nameEl.setAttribute("value", name);
    nameEl.setAttribute("size", name.length.toString());

    var editPage = document.createElement("button");
    editPage.classList.add("edit-page");
    editPage.insertBefore(document.createTextNode("Edit Page"), null);

    var swapWithElBefore = document.createElement("button");
    swapWithElBefore.insertBefore(
        document.createTextNode(
            String.fromCodePoint(UP_ARROW_UTF16_CODE_POINT)), null);

    var swapWithElAfter = document.createElement("button");
    swapWithElAfter.insertBefore(
        document.createTextNode(
            String.fromCodePoint(DOWN_ARROW_UTF16_CODE_POINT)), null);

    var moveAfterElParent = document.createElement("button");
    moveAfterElParent.insertBefore(
        document.createTextNode(
            String.fromCodePoint(LEFT_ARROW_UTF16_CODE_POINT)), null);

    var makeChildOfElBefore = document.createElement("button");
    makeChildOfElBefore.insertBefore(
        document.createTextNode(
            String.fromCodePoint(RIGHT_ARROW_UTF16_CODE_POINT)), null);

    var deleteEl = document.createElement("button");
    deleteEl.insertBefore(
        document.createTextNode(
            String.fromCodePoint(TIMES_UTF16_CODE_POINT)), null);

    var addAfterEl = document.createElement("button");
    addAfterEl.insertBefore(document.createTextNode("+"), null);

    rowEl.insertBefore(nameEl             , null);
    rowEl.insertBefore(editPage           , null);
    rowEl.insertBefore(swapWithElBefore   , null);
    rowEl.insertBefore(swapWithElAfter    , null);
    rowEl.insertBefore(makeChildOfElBefore, null);
    rowEl.insertBefore(moveAfterElParent  , null);
    rowEl.insertBefore(deleteEl           , null);
    rowEl.insertBefore(addAfterEl         , null);

    fileTreeNodeEl.insertBefore(rowEl, null);

    return fileTreeNodeEl;
}

/** @return {HTMLElement} **/
function fileTreeNodeEnsureSublistEl(el) {
    if (!el.lastChild || el.lastChild.nodeName != "UL") {
        el.insertBefore(document.createElement("ul"), null);
    }
    return el.lastChild;
}

/** @param   {HTMLElement} parentEl
 *  @param   {string     } childName
 *  @returns {HTMLElement} **/
function fileTreeAdd(parentEl, childName) {
    var  listEl = fileTreeNodeEnsureSublistEl(parentEl);
    var childEl = newFileTreeNodeEl(childName);
    listEl.insertBefore(childEl, null);
    return childEl;
}

var mainEl = DUMMY_EL;

var alreadyHandledWindowLoad = false;

/** @param {Event} event **/
function handleEvent(event) {
    var ensureStillEditTargetAtEndOfFunc    = false;
    var sendRequestToSaveHTMLDocAtEndOfFunc = false;

    if ((event.type === "load" || event.type === "DOMContentLoaded") &&
        !alreadyHandledWindowLoad
    ) {
        console.info("Handling window load.");

        alreadyHandledWindowLoad = true;

        mainEl = document.body.firstElementChild;
        document.body.style.setProperty("max-width", "800px");
        document.body.insertBefore(fileTreeEl, mainEl);
        document.body.style.setProperty("display", "flex");
        document.body.style.setProperty("flex-direction", "row");

        fileTreeAdd(fileTreeEl, "foo");
        var barEl = fileTreeAdd(fileTreeEl, "bar");
        fileTreeAdd(barEl, "a");
        fileTreeAdd(barEl, "b");
        fileTreeAdd(fileTreeEl, "baz");

        ensureStillEditTargetAtEndOfFunc = true;
    } else if (event.type === "touchstart" || event.type === "mousedown")
    handleClick: {
        if (!event.target) { break handleClick; }
        if (event.target.nodeName === "H1" ||
            event.target.nodeName === "P"  ||
            event.target.nodeName === "IMG"
        ) {
            editTargetEl.removeAttribute("contenteditable");
            editTargetEl = event.target;

            ensureStillEditTargetAtEndOfFunc = true;
            break handleClick;
        }

        var eventTargetIsEditControl =
            event.target.compareDocumentPosition(editControls)
            & Node.DOCUMENT_POSITION_CONTAINS;
        if (eventTargetIsEditControl) {
            if (event.type === "touchstart") { break handleClick; }

            event.preventDefault();
            event.stopPropagation();

            if (event.target === editToggleItalic) {
                document.execCommand("italic", false, null);
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }
            if (event.target === editToggleBold) {
                document.execCommand("bold", false, null);
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }
            if (event.target === editToggleUnderline) {
                document.execCommand("underline", false, null);
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }
            if (event.target === editToggleStrikethrough) {
                document.execCommand("strikethrough", false, null);
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }

            if (event.target === editSwaptWithElBefore) {
                editTargetEl.removeAttribute("contenteditable");
                var elBefore = editTargetEl.previousElementSibling;
                if (!elBefore) { return; }
                editTargetEl.parentNode.insertBefore(editTargetEl, elBefore);
                ensureStillEditTargetAtEndOfFunc    = true;
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }
            if (event.target === editSwaptWithElAfter) {
                editTargetEl.removeAttribute("contenteditable");
                var elAfter = editTargetEl.nextElementSibling;
                if (elAfter === editControls)
                    { elAfter = elAfter.nextElementSibling; }
                if (!elAfter) { return; }
                editTargetEl.parentNode
                    .insertBefore(editTargetEl, elAfter.nextElementSibling);
                ensureStillEditTargetAtEndOfFunc    = true;
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }
            if (event.target === editDelete) {
                var elAfter = editTargetEl.nextElementSibling;
                if (elAfter === editControls)
                    { elAfter = elAfter.nextElementSibling; }
                editTargetEl.parentNode.removeChild(editTargetEl);
                editTargetEl = elAfter || DUMMY_EL;
                ensureStillEditTargetAtEndOfFunc    = true;
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
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
                ensureStillEditTargetAtEndOfFunc    = true;
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
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
                ensureStillEditTargetAtEndOfFunc    = true;
                sendRequestToSaveHTMLDocAtEndOfFunc = true;;
                break handleClick;
            }
            if (event.target === editAddImageAfter) {
                editTargetEl.removeAttribute("contenteditable");
                var elAfter = editTargetEl.nextElementSibling;
                if (elAfter === editControls)
                    { elAfter = elAfter.nextElementSibling; }
                var parentNode = editTargetEl.parentNode;
                fileUploadInputEl.setAttribute("accept", "image/*");
                fileUploadInputEl.click();
                break handleClick;
            }
            break handleClick;
        }

        var eventTargetIsInFileTree =
            event.target.compareDocumentPosition(fileTreeEl)
            & Node.DOCUMENT_POSITION_CONTAINS;
        if (eventTargetIsInFileTree) {
            /** @type {HTMLElement} **/
            var fileTreeNodeEl = event.target.parentNode.parentNode;
            var utf16Code      = event.target.textContent.codePointAt(0);
            // Swap with element before
            if (utf16Code === UP_ARROW_UTF16_CODE_POINT) {
                var elBefore = fileTreeNodeEl.previousElementSibling;
                fileTreeNodeEl.parentNode.insertBefore(fileTreeNodeEl, elBefore);
            }
            // Swap with element after
            if (utf16Code === DOWN_ARROW_UTF16_CODE_POINT) {
                var elAfter = fileTreeNodeEl.nextElementSibling;
                if (!elAfter) { return; }
                fileTreeNodeEl.parentNode
                    .insertBefore(fileTreeNodeEl, elAfter.nextElementSibling);
            }
            // Move after parent tree node element
            if (utf16Code == LEFT_ARROW_UTF16_CODE_POINT) {
                /** @type {HTMLElement} **/
                var parentTreeNodeEl = fileTreeNodeEl.parentNode;
                if (parentTreeNodeEl === fileTreeEl) { return; }
                parentTreeNodeEl = parentTreeNodeEl.parentNode;
                if (parentTreeNodeEl === fileTreeEl) { return; }
                parentTreeNodeEl.parentNode
                    .insertBefore(fileTreeNodeEl,
                                  parentTreeNodeEl.nextElementSibling);
            }
            // Make child of element before
            if (utf16Code == RIGHT_ARROW_UTF16_CODE_POINT) {
                /** @type {HTMLElement} **/
                var elBefore = fileTreeNodeEl.previousSibling;
                if (!elBefore) { return; }
                var listEl = fileTreeNodeEnsureSublistEl(elBefore);
                listEl.insertBefore(fileTreeNodeEl, null);
            }
            // Delete
            if (utf16Code === TIMES_UTF16_CODE_POINT) {
                fileTreeNodeEl.parentNode.removeChild(fileTreeNodeEl);
            }
            // Add after
            if (utf16Code === "+".codePointAt(0)) {
                var newEl = newFileTreeNodeEl("New File");
                var elAfter = fileTreeNodeEl.nextElementSibling;
                fileTreeNodeEl.parentNode.insertBefore(newEl, elAfter);
            }
            break handleClick;
        }
    } else if (event.type === "input" && event.target === editTargetEl) {
        sendRequestToSaveHTMLDocAtEndOfFunc = true;;
    } else if (event.type === "change" && event.target === fileUploadInputEl) {
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
        ensureStillEditTargetAtEndOfFunc    = true;
        sendRequestToSaveHTMLDocAtEndOfFunc = true;;
    } else if (event.type == "readystatechange" &&
        event.target instanceof XMLHttpRequest
    ) {
        /** @type {XMLHttpRequest} **/
        var request = event.target;
        if (request.readyState === XMLHttpRequest.DONE) {
            if (request.status === 201) {
                console.info("Successfully saved the HTML Document to the server.");
            } else {
                console.error("Failed to save the HTML Document to the server.");
            }
        }
    }

    if (ensureStillEditTargetAtEndOfFunc) {
        if (editTargetEl === DUMMY_EL) {
            if (!mainEl) { return false; }
            if (!mainEl.firstElementChild || (
                mainEl.firstElementChild.nodeName !== "H1" &&
                mainEl.firstElementChild.nodeName !== "P"  &&
                mainEl.firstElementChild.nodeName !== "IMG"
            )) {
                editTargetEl = document.createElement("H1");
                editTargetEl.insertBefore(
                    document.createTextNode("Heading 1."), null);
                mainEl.insertBefore(editTargetEl, null);
            } else {
                editTargetEl = mainEl.firstElementChild;
            }
        }
        editTargetEl.setAttribute("contenteditable", "");
        editTargetEl.focus();
        editTargetEl.parentNode
            .insertBefore(editControls, editTargetEl.nextElementSibling);
    }

    if (sendRequestToSaveHTMLDocAtEndOfFunc) {
        editTargetEl.removeAttribute("contenteditable");

        var tempHtmlDoc = document.implementation.createHTMLDocument();
        var htmlElClone = tempHtmlDoc.importNode(document.documentElement, true);
        tempHtmlDoc.removeChild(tempHtmlDoc.documentElement);
        tempHtmlDoc.insertBefore(htmlElClone, null);
        tempHtmlDoc.body.removeAttribute("style");
        tempHtmlDoc.getElementById("file-tree"    ).remove();
        tempHtmlDoc.getElementById("edit-controls").remove();

        var request = new XMLHttpRequest();
        request.addEventListener("readystatechange", handleEvent);
        request.open("PUT", document.URL);
        request.send(tempHtmlDoc);

        editTargetEl.setAttribute("contenteditable", "");
    }
}

window.addEventListener("load"             , handleEvent);
window.addEventListener("DOMContentLoaded" , handleEvent);
window.addEventListener("touchstart"       , handleEvent);
window.addEventListener("mousedown"        , handleEvent);
window.addEventListener("input"            , handleEvent);
fileUploadInputEl.addEventListener("change", handleEvent);

