#!/usr/bin/env python
""" Plagiarism source retrieval example.

    This program provides an example of plagiarism source retrieval
    for the PAN 2013 Plagiarism Detection task.
"""
from __future__ import division, unicode_literals
#__author__ = 'Martin Potthast'
#__email__ = 'martin.potthast@uni-weimar.de'
__version__ = '3.0'

import codecs
import string
import glob
import os
import random
import re
import simplejson
import sys
import time
import unicodedata
import urllib
import urllib2
import nltk
from nltk.corpus import stopwords
import math
from text.blob import TextBlob

CHATNOIR = 'http://webis15.medien.uni-weimar.de/proxy/chatnoir/batchquery.json'  
CLUEWEB = 'http://webis15.medien.uni-weimar.de/proxy/clueweb/id/'

STOPWORD =[]
STOPWORD += ['would' , 'said' , 'left' , 'right' , 'interest']



# Source Retrieval Example
# ========================

""" The following class implements a naive strategy to retrieve sources for a 
given suspicious document. It is merely intended as an example, not as a
serious solution to the problem.
"""

class Example:
    def process(self, suspdoc, outdir, token, bloblist, count):
        """ Run the source retrieval pipeline. """		
        f=open("results.txt","w")
        thelist=[]
        download=[]
        download_url=[]
        #print bloblist,len(bloblist)
        tfidf=self.rs(bloblist)
        #print tfidf
        self.stopword(STOPWORD)
        # Extract the ID and initiate the log writer.
        self.init(suspdoc, outdir)
        # Extract queries from the suspicious document.
        open_queries = self.extract_queries(tfidf, count)
		#print open_queries
        while len(open_queries) > 0:
            # Retrieve search results for the first query.
            query = open_queries.pop()
            print query
            results = self.pose_query(query, token)
            thelist.append(results)
            for item in thelist:
                f.write("%s\n" % item)			
            #print results
            # Log the query event.
            self.log(query)
            # Download the first-ranked result, if any.
            if results["chatnoir-batch-results"][0]["results"] == 0:
                continue;  # The query returned no results.
            download, download_url = self.download_first_result(results, token)
            #print download
            # Log the download event.
            for i in range(0,len(download_url)):
                self.log(download_url[i])
                print download_url[i]
                self.check_oracle(download[i])
        # Close the log writer.
        self.teardown()
        


    def init(self, suspdoc, outdir):
        """ Sets up the output file in which the log events will be written. """
        logdoc = ''.join([suspdoc[:-4], '.log'])
        logdoc = ''.join([outdir, os.sep, logdoc[-26:]])
        self.logwriter = open(logdoc, "w")
        self.suspdoc_id = int(suspdoc[-7:-4])  # Extracts the three digit ID.
    
	

    def teardown(self):
        self.logwriter.close()

    def tf(self, word, blob):
        return float(blob.words.count(word) / len(blob.words))

    def n_containing(self,word, bloblist):
        return sum(1 for blob in bloblist if word in blob)
	
    def idf(self, word, bloblist):
        return (math.log(  (len(bloblist) / (1 + self.n_containing(word, bloblist) ) )  ))

    def tfidf(self, word, blob, bloblist):
        return self.tf(word, blob) * self.idf(word, bloblist)
         
    def rs(self, bloblist):
        tflist=[]
        tflist2=[]
        for i, blob in enumerate(bloblist):
            print("Top words in document {}".format(i + 1))
            scores = {word: self.tfidf(word, blob, bloblist) for word in blob.words}
            sorted_words = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            i=0
            while i< len(sorted_words):
                if sorted_words[i][0] in STOPWORD:
				    del sorted_words[i]
                else:
                    i=i+1				
            
            for word, score in sorted_words[:20]:
                print("\tWord: {}, TF-IDF: {}".format(word, round(score, 5)))    
                tflist.append(word)
				
            #print tflist
            tflist2.append(tflist)
            tflist=[]
        
        return tflist2
        #print len(tflist2)

    def stopword(self,STOPWORD):
        sp=[]
        sp=open('stopword.txt','r')
        self.lines=sp.readlines()
        for line in self.lines:
		    STOPWORD.append(line[:-1])
        
        return STOPWORD
	
        				

    def read_file(self, suspdoc): 
        """ Reads the file suspdoc and returns its text content. """
        f = codecs.open(suspdoc, 'r', 'utf-8')
        text = f.read()
        f.close()
        return text


    


    def extract_queries(self, tfidf, count): 
        """ Creates two queries by selecting three random token per query. """
        extract_query=[]
        a=' '.join([tfidf[count][15],tfidf[count][16],tfidf[count][17],tfidf[count][18],tfidf[count][19]])
        extract_query.append(a)
        a=' '.join([tfidf[count][10],tfidf[count][11],tfidf[count][12],tfidf[count][13],tfidf[count][14]])			
        extract_query.append(a)
        a=' '.join([tfidf[count][5],tfidf[count][6],tfidf[count][7],tfidf[count][8],tfidf[count][9]])
        extract_query.append(a)
        a=' '.join([tfidf[count][0],tfidf[count][1],tfidf[count][2],tfidf[count][3],tfidf[count][4]])			
        extract_query.append(a)
        return extract_query

    def pose_query(self, query, token): 
        """ Poses the query to the ChatNoir search engine. """
        # Double curly braces are escaped curly braces, so that format
        # strings will still work.   
        json_query = u"""
        {{
           "max-results": 200,
           "suspicious-docid": {suspdoc_id},
           "queries": [
             {{
               "query-string": "{query}"
             }}
           ]
        }}
        """.format(suspdoc_id = self.suspdoc_id, query = query)
        #print json_query
        json_query = \
            unicodedata.normalize("NFKD", json_query).encode("ascii", "ignore")
        request = urllib2.Request(CHATNOIR, json_query)
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        request.add_header("Authorization", token)
        request.get_method = lambda: 'POST'
        try:
            response = urllib2.urlopen(request)
            results = simplejson.loads(response.read())
            response.close()
            #print("----------------results----------------")
            #print results
            return results
        except urllib2.HTTPError as e:
            error_message = e.read()
            print >> sys.stderr, error_message
            sys.exit(1)


    def download_first_result(self, results, token):
        first_result=[]
        document_id=[]
        document_url=[]
        request=[]
        rlists=[]
        download=[]
        for i in range(0,len(results["chatnoir-batch-results"][0]["result-data"])):
            first_result.append(results["chatnoir-batch-results"][0]["result-data"][i])
            document_id.append(first_result[i]["longid"])
            document_url.append(first_result[i]["url"])
            request.append(urllib2.Request(CLUEWEB + str(document_id[i])))
            request[i].add_header("Accept", "application/json")
            request[i].add_header("Authorization", token)
            request[i].add_header("suspicious-docid", str(self.suspdoc_id))
            request[i].get_method = lambda: 'GET'
        
        
        for i in range(0,len(request)):
            try:
                response=urllib2.urlopen(request[i])
                rlists.append(response)
                download.append(simplejson.loads(rlists[i].read()))
                response.close()
            except urllib2.HTTPError as e:
                error_message = e.read()
                print >> sys.stderr, error_message
                sys.exit(1)
			   
        return download, document_url
        
    
    
    def check_oracle(self, download):

        if download["oracle"] == "source":
            print("Success: a source has been retrieved.")
            self.log("Successsssssssssssssssssssssssssssssssss")
        else:
            print("Fail")



    def log(self, message):
        """ Writes the message to the log writer, prepending a timestamp. """
        timestamp = int(time.time())  # Unix timestamp
        self.logwriter.write(' '.join([str(timestamp), message]))
        self.logwriter.write('\n')


# Main
# ====

if __name__ == "__main__":
    """ Process the commandline arguments. We expect three arguments: 
        - The path to the directory where suspicious documents are located.
        - The path to the directory to which output shall be written.
        - The access token to the PAN search API.
    """
    if len(sys.argv) == 3:
        suspdir = sys.argv[1]
        outdir  = sys.argv[2]
        token   = "7eb96d7390b5f76d6fc4ffb175eaedac"
        suspdocs = glob.glob(suspdir + os.sep + 'suspicious-document?????.txt')
        

        bloblist=[]
        count=0
        for suspdoc in suspdocs:
            f = codecs.open(suspdoc, 'r', 'utf-8')
            text = f.read()
            blob = TextBlob(text.lower())
            f.close()
            bloblist.append(blob)
			
		    
        for suspdoc in suspdocs:
            print ("Processing " + suspdoc)
            example = Example()
            example.process(suspdoc, outdir, token , bloblist,count)
            count+=1
    else:
        print('\n'.join(["Unexpected number of command line arguments.",
        "Usage: ./pan13_source_retrieval_example.py {susp-dir} {out-dir} {token}"]))
