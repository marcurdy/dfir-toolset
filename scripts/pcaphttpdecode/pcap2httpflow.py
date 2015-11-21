#!/usr/bin/env python
# reads a pcap file extract http content and decompress gzip data into html and javascripts files (.html + .js)
# if a pcap file with multiple streams is supplied, too many javascript + html files will be supplied. 
# works best if the pcap is splitted in unique reassembled streams. 
# See Honeynet Forensics Challenge #2 proposed solution (feb2010)
# Angelo Dell'Aera 'buffer' – Honeynet Italian Chapter

import sys, StringIO, dpkt, gzip
from HTMLParser import HTMLParser


class JSCollect(HTMLParser):
    def __init__(self):
        self.scripts  = []
        self.inScript = False
        HTMLParser.__init__(self)

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.data     = ''
            self.inScript = True

    def handle_data(self, data):
        if self.inScript:
            self.data += data

    def handle_endtag(self, tag):
        if tag == 'script':
            self.scripts.append(self.data)
            self.data = ''
            self.inScript = False

    def get_scripts(self):
        return self.scripts


class PCAPParser:
    def __init__(self, filename):
        self.filename      = filename
        self.summary       = open("summary.txt", 'w')
        self.streamcounter = 0
        self.parser        = JSCollect()
        self.conn          = dict()
        self.parse_pcap_file()

    def check_eth(self):
        return self.eth.type != dpkt.ethernet.ETH_TYPE_IP

    def check_ip(self):
        return self.ip.p != dpkt.ip.IP_PROTO_TCP

    def html_analyze(self, http):
        if 'content-encoding' in http.headers and http.headers['content-encoding'] == 'gzip':
            data = StringIO.StringIO(http.body)
            gzipper = gzip.GzipFile(fileobj = data)
            html = gzipper.read()
        else:
            html = http.body
        
        self.streamcounter += 1
        return html

    def save_stream(self, filename, content):
        try:
            fd = open(filename, 'w')
            fd.write(content)
            fd.close()
            print "content saved in: %s" % (filename)
        except:
            print "Error opening the file %s and writing in it" % (filename, )

    def parse_pcap_file(self):
        i = 0
        # Open the pcap file
        f = open(self.filename)
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            self.eth = dpkt.ethernet.Ethernet(buf)
            if self.check_eth():
                continue

            self.ip = self.eth.data
            if self.check_ip():
                continue

            self.tcp = self.ip.data
            tupl = (self.ip.src, self.ip.dst, self.tcp.sport, self.tcp.dport)

            # Ensure these are in order! TODO change to a defaultdict
            if tupl in self.conn:
                self.conn[tupl] = self.conn[tupl] + self.tcp.data
            else:
                self.conn[tupl] = self.tcp.data

            # Try and parse what we have
            try:
                stream = self.conn[tupl]
                if stream[:4] == 'HTTP':
                    http = dpkt.http.Response(stream)

                    if 'content-type' in http.headers and http.headers['content-type'] == 'text/html':
                        html = self.html_analyze(http)
                        if len(html):
                            htmlfile = "%s.stream.%s.html" % (self.filename, str(self.streamcounter)) 
                            self.save_stream(htmlfile, html)

                            self.parser.feed(html)
                            for script in self.parser.get_scripts(): 
                                jsfile = "%s.stream.%s_%s.js" % (self.filename, str(self.streamcounter), str(i))
                                self.save_stream(jsfile, script)
                                #print script
                                i += 1
                            self.summary.write("Stream: %d (Response) --> %s \n"
                                               % (self.streamcounter, http.status) )
                else:
                    http = dpkt.http.Request(stream)
                    print "[+] %s%s (%s)" % (http.headers['host'], http.uri, http.method)
                    self.summary.write("Stream %d (Request) --> URL: %s%s\n" % (self.streamcounter,
                                        http.headers['host'], http.uri)) 
                    self.streamcounter += 1

                # If we reached this part an exception hasn't been thrown
                stream = stream[len(http):]
                if len(stream) == 0:
                    del self.conn[tupl]
                else:
                    self.conn[tupl] = stream

            except dpkt.UnpackError:
                pass

        f.close()
        self.summary.close()

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "%s " % sys.argv[0]
        sys.exit(2)

    PCAPParser(sys.argv[1])
