NEWLINE_CHAR_CODE = ord('\n')

sitemap              = bytearray(16*1024)
sitemap_len          = 0
sitemap_pos          = 0
sitemap_indent_depth = 0
sitemap_indent       = b"  "

def sitemap_insert_indent():
    global sitemap_pos
    for _ in range(sitemap_indent_depth):
        sitemap_insert(sitemap_indent)    

def sitemap_insert(bytes_):
    global sitemap_pos
    for i, b in enumerate(bytes_):
        sitemap[sitemap_pos] = b
        sitemap_pos += 1

        if b == NEWLINE_CHAR_CODE:
            sitemap_insert_indent()        

def sitemap_advance_if_ahead(expected):
    global sitemap_pos
    n = len(expected)
    if sitemap[sitemap_pos:sitemap_pos+n] == expected:
        sitemap_pos += n
        return True
    else:
        return False

def sitemap_skip_whitespace():
    global sitemap_pos
    while sitemap[sitemap_pos] in b" \n\t\r\f\v":
        sitemap_pos += 1

def sitemap_tag_open(tag_name):
    global sitemap_pos, sitemap_indent_depth

    sitemap_skip_whitespace()

    opening_tag = b"<" + tag_name + b">"
    if not sitemap_advance_if_ahead(opening_tag):
        if sitemap_pos != 0 and sitemap[sitemap_pos-1] != b"\n":
            sitemap_insert(b"\n")
        sitemap_insert(opening_tag)
    sitemap_indent_depth += 1

def sitemap_tag_close(tag_name, on_newline):
    global sitemap_pos, sitemap_indent_depth

    sitemap_skip_whitespace()

    sitemap_indent_depth -= 1
    closing_tag = b"</" + tag_name + b">"
    if not sitemap_advance_if_ahead(closing_tag):
        if on_newline and sitemap_pos != 0 and sitemap[sitemap_pos-1] != b"\n":
            sitemap_insert(b"\n")
        sitemap_insert(closing_tag)

def sitemap_begin():
    global sitemap_pos, sitemap_indent_depth
    sitemap_pos = 0

    sitemap_tag_open(b"?xml version='1.0' encoding='UTF-8'?")
    sitemap_indent_depth -= 1
    sitemap_tag_open(b"urlset "
        b"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
        b"xsi:schemaLocation=\"http://www.sitemaps.org/schemas/sitemap/0.9\" "
                           b"\"http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd\" "
        b"xmlns=\"http://www.sitemaps.org/schemas/0.9\"")

def sitemap_end():
    global sitemap_len, sitemap_indent_depth
    sitemap_tag_close(b"urlset", True)
    sitemap_len = sitemap_pos

sitemap_begin()
sitemap_tag_open(b"url")
sitemap_tag_open(b"loc")
sitemap_insert(b"http://example.com/foo")
sitemap_tag_close(b"loc", False)
sitemap_tag_close(b"url", True)
sitemap_end()
sitemap_str = sitemap[:sitemap_len].decode("utf8")
print(sitemap_str)

