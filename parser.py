from html.parser import HTMLParser

'''
HTML Parser class that queues links to visit and checks for secret flags.
'''
class Parser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.secret_flags = []
        self.urls_queued = []
        self.urls_crawled = set()
        self.tag = ""
        self.attrs = ""

    def handle_starttag(self, tag, attrs):
        '''
        Function:   handle_starttag - looks for 'a' tags with 'href' attributes
                                    - adds href links to the url queue to crawl
        Parameters: tag - the html tag
                    attrs - the attributes of the tag
        Return:     no return, only appends to urls_queued
        '''
        self.tag = tag
        self.attrs = attrs
        if (tag == "a"):
            for attr in attrs:
                if attr[0] == "href":
                    if (attr[1] not in self.urls_queued) and (attr[1] not in self.urls_crawled):
                        self.urls_queued.append(attr[1])

    def handle_data(self, data):
        '''
        Function:   handle_data - looks for 'h2' tags containing the secret flags
                                - finds tags with class 'secret_flag' and adds it to list of flags
        Parameters: data - the data inside the html tag
        Return:     no return, only appends to secret_flags
        '''
        # if tag is h2 -> check attrs
        if (self.tag == "h2"):
            # if class attr is secret_flag -> get flag
            for attr in self.attrs:
                if (attr[0] == "class") and (attr[1] == "secret_flag"):
                    if "\n" not in data:
                        self.secret_flags.append(data.split(": ")[1])
