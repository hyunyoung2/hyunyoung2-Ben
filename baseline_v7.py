#!/usr/bin/env python

__version__ = '7.0'


import os
import string
import sys
import xml.dom.minidom
import codecs
import re
import nltk
from nltk.corpus import stopwords
from nltk.tag.stanford import POSTagger

# Stanford POS Tagger
# ===================

nltk.internals.config_java("C:\\Program Files\\Java\\jdk1.7.0_11\\bin\\java.exe")
Java_path="C:\\Program Files\\Java\\jdk1.7.0_11\\bin\\java.exe"
os.environ['JAVA_HOME']=Java_path
ModelPath = "C:\\Python27\\stanford-postagger-full-2014-01-04\\models\\english-bidirectional-distsim.tagger"
JarPath = "C:\\Python27\\stanford-postagger-full-2014-01-04\\stanford-postagger-3.3.1.jar"
tagger = POSTagger(ModelPath, JarPath)

# Const
# =====

compareNumWords = 20

STOPWORD = []
STOPWORD += ['would' , 'said' , 'left' , 'right' , 'interest']
ImportantTag=['JJ', 'JJR', 'JJS', 'NN', 'NNP', 'NNPS', 'NNS', 'RB', 'RBR', 'RBS', 'SYM', 'VB', 'VBD', 'VBG', 'VBZ', 'VBN', 'VBP']

# Helper functions
# ================

def tokenize(text):

    """ Tokenize a given text and return a dict containing all start and end
    positions for each token.
    Characters defined in the global string DELETECHARS will be ignored.

    Keyword arguments:
    text   -- the text to tokenize
    length -- the length of each token
    """
    
    tokens = {}
    text = re.sub(r'[^\w\s]','',text).lower()
    token = [(m.group(0), (m.start(), m.end() - 1)) for m in re.finditer(r'[%s]+'%string.ascii_letters, text)]
    token_susp = []

    for i in range(0, len(token)):
        tag = tagger.tag(token[i][0].split())
        wordTag = tag[0][1]

        if token[i][0] not in STOPWORD:
            if wordTag in ImportantTag:
                if len(token[i][0]) > 3:
                    token_susp.append(token[i])

                    if token[i][0] not in tokens:
                        tokens[token[i][0]] = []
                    tokens[token[i][0]].append(token[i][1])

    return tokens, token_susp

def serialize_features(susp, src, features, outdir):
    
    """ Serialze a feature list into a xml file.
    The xml is structured as described in
    http://www.webis.de/research/corpora/pan-pc-12/pan12/readme.txt
    The filename will follow the naming scheme {susp}-{src}.xml and is located
    in the current directory.  Existing files will be overwritten.

    Keyword arguments:
    susp     -- the filename of the suspicious document
    src      -- the filename of the source document
    features -- a list containing feature-tuples of the form
                ((start_pos_susp, end_pos_susp),
                 (start_pos_src, end_pos_src))
    """

    impl = xml.dom.minidom.getDOMImplementation()
    doc = impl.createDocument(None, 'document', None)
    root = doc.documentElement
    root.setAttribute('reference', susp)
    doc.createElement('feature')

    for f in features:
        feature = doc.createElement('feature')
        feature.setAttribute('name', 'detected-plagiarism')
        feature.setAttribute('this_offset', str(f[1][0]))
        feature.setAttribute('this_length', str(f[1][1] - f[1][0]))
        feature.setAttribute('source_reference', src)
        feature.setAttribute('source_offset', str(f[0][0]))
        feature.setAttribute('source_length', str(f[0][1] - f[0][0]))
        root.appendChild(feature)

    doc.writexml(open(outdir + susp.split('.')[0] + '-'
                      + src.split('.')[0] + '.xml', 'w'),
                 encoding='utf-8')


# Plagiarism pipeline
# ===================

""" The following class implement a very basic baseline comparison, which
aims at near duplicate plagiarism. It is only intended to show a simple
pipeline your plagiarism detector can follow.
Replace the single steps with your implementation to get started.
"""

class Baseline:
    def __init__(self, susp, src, outdir):
        self.susp = susp
        self.src = src
        self.susp_file = os.path.split(susp)[1]
        self.src_file = os.path.split(src)[1]
        self.susp_id = os.path.splitext(susp)[0]
        self.src_id = os.path.splitext(src)[0]
        self.output = self.susp_id + '-' + self.src_id + '.xml'
        self.detections = None
	self.outdir=outdir

    def process(self):
        """ Process the plagiarism pipeline. """
        self.preprocess()
        self.detections = self.compare()
        self.postprocess()

    def preprocess(self):
        """ Preprocess the suspicious and source document. """

        susp_fp = codecs.open(self.susp, 'r', 'utf-8')
        self.susp_text = susp_fp.read()
        self.tokens, self.token_susp = tokenize(self.susp_text)
        susp_fp.close()

        src_fp = codecs.open(self.src, 'r', 'utf-8')
        self.src_text = src_fp.read()
        src_fp.close()
		
    def compare(self):
        """ Test a suspicious document for near-duplicate plagiarism with regards to
        a source document and return a feature list.
        """

        txt = re.sub(r'[^\w\s]','',self.src_text).lower()
        token = [(m.group(0), (m.start(), m.end() - 1)) for m in re.finditer(r'[%s]+'%string.ascii_letters, txt)]
        token_src = []
        detections = []
        skipto = -1

        for i in range(0, len(token)):
            tag = tagger.tag(token[i][0].split())
            wordTag = tag[0][1]

            if token[i][0] not in STOPWORD:
                if wordTag in ImportantTag:
                    if len(token[i][0]) > 3:
                        token_src.append(token[i])

        for i in range(0, len(token_src)):
            if i > skipto:
                if token_src[i][0] in self.tokens:
                    for tup in self.tokens[token_src[i][0]]:
                        w = 0
                        for j in range(0, len(self.token_susp)):
                            if self.token_susp[j][0] == token_src[i][0]:
                                w = j
                                break

                        src_list = []
                        susp_list = []

                        start_src_list = token_src[i][1][0]
                        start_susp_list = tup[0]

                        src_list_size = 0
                        susp_list_size = 0
                        
                        while (start_src_list < len(self.src_text) and
                               start_susp_list < len(self.susp_text) and
                               src_list_size < compareNumWords and
                               susp_list_size < compareNumWords):
                            src_list.append(token_src[i+src_list_size][0])
                            susp_list.append(self.token_susp[w+susp_list_size][0])
                            
                            start_src_list = token_src[i+src_list_size][1][0] + 1
                            start_susp_list = self.token_susp[w+susp_list_size][1][0] + 1

                            src_list_size = src_list_size + 1
                            susp_list_size = susp_list_size + 1

                        skipto = start_src_list

                        S1 = set(src_list)
                        S2 = set(susp_list)
                        difference = S1.symmetric_difference(S2)
                        difference_size = len(difference)
 
                        while(start_src_list < len(self.src_text) and
                              start_susp_list < len(self.susp_text) and
                              difference_size < compareNumWords):
                            print start_src_list
                            print self.src_text
                            src_list.append(token_src[i+src_list_size][0])
                            susp_list.append(self.token_susp[w+susp_list_size][0])

                            start_src_list = token_src[i+src_list_size][1][0] + 1
                            start_susp_list = self.token_susp[w+susp_list_size][1][0] + 1

                            src_list_size = src_list_size + 1
                            susp_list_size = susp_list_size + 1

                            S1 = set(src_list)
                            S2 = set(susp_list)
                            difference = S1.symmetric_difference(S2)
                            difference_size = len(difference)

                        skipto = start_src_list
                        d = ((token_src[i][1], start_src_list-1), (self.tokens[token_src[i][0]][0][0], start_susp_list-1))
                        
                        detections.append(d)

        return detections

    def postprocess(self):
        """ Postprocess the results. """
        serialize_features(self.susp_file, self.src_file, self.detections, self.outdir)

# Main
# ====

if __name__ == "__main__":
    """ Process the commandline arguments. We expect three arguments: The path
    pointing to the pairs file and the paths pointing to the directories where
    the actual source and suspicious documents are located.
    """
	
    if len(sys.argv) == 5:
        srcdir = sys.argv[2]
        suspdir = sys.argv[3]
        outdir = sys.argv[4]
        if outdir[-1] != "/":
            outdir+="/"
        lines = open(sys.argv[1], 'r').readlines()
        for line in lines:
            susp, src = line.split()
            baseline = Baseline(os.path.join(suspdir, susp),
                                os.path.join(srcdir, src), outdir)
            baseline.process()
    else:
        print('\n'.join(["Unexpected number of commandline arguments.",
                         "Usage: ./pan13-plagiarism-text-alignment-example.py {pairs} {src-dir} {susp-dir} {out-dir}"]))
