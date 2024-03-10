# -*- coding: utf-8 -*-
"""
Created on Mon Feb 26 12:14:07 2024

@author: Suresh
"""
import streamlit as st
st.set_page_config(
    page_title="Multipage App"
    )


import numpy as np
import pandas as pd
import streamlit as st
import pickle
import re
from urllib.parse import urlparse
from tld import get_tld
#import os.path
loaded_model1=pickle.load(open("project_model_final_2.sav","rb"))

def pred(input):
    test=get_prediction_from_url(input)
    tt=loaded_model1.predict(test)
    if int(tt[0]) == 0:
        
        res="SAFE"
        return res
    elif int(tt[0]) == 1.0:
        
        res="DEFACEMENT"
        return res
    elif int(tt[0]) == 2.0:
        res="PHISHING"
        return res
        
    elif int(tt[0]) == 3.0:
        
        res="MALWARE"
        return res
    
def get_prediction_from_url(test_url):
    features_test = main1(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))
    return features_test

def main1(url):
    
    status = []
    
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)
      
    status.append(tld_length(tld))
    
    
    

    return status


#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0



def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
       
        # print 'No matching pattern found'
        return 0
    


def count_dot(url):
    count_dot = url.count('.')
   
    return count_dot


def count_www(url):
    d=url.count('www')
    return d



def count_atrate(url):
    e=url.count('@')
    return e




def no_of_dir(url):
    urldir = urlparse(url).path
    f=urldir.count('/')
    return f



def no_of_embed(url):
    urldir = urlparse(url).path
    
    return urldir.count('//')




def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
       
        return 1
    else:
        
        return 0
    
    


def count_https(url):
    
    return url.count('https')


def count_http(url):
    
    return url.count('http')


def count_per(url):
    
    return url.count('%')


def count_ques(url):
   
    return url.count('?')


def count_hyphen(url):
    
    return url.count('-')


def count_equal(url):
   
    return url.count('=')


def url_length(url):
    
    return len(str(url))




def hostname_length(url):
    
    return len(urlparse(url).netloc)




def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        
        return 1
    else:
        
        return 0



def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    
    return digits




def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
  
    return letters






def fd_length(url):
    urlpath= urlparse(url).path
    try:
        
        return len(urlpath.split('/')[1])
    except:
     
        return 0



def tld_length(tld):
    try:
        
        return len(tld)
    except:
        
        return -1


    
def main():
    
    
    st.markdown("<h1 style='text-align: left; color: red ; margin-top:0px;'>MALICIOUS URL DETECTION AND CLASSIFICATION</h1>", unsafe_allow_html=True)
    #st.title("MALICIOUS URL DETECTION AND CLASSIFICATION")
    st.write("**Note** : Welcome to our Malicious URL Detection and Classification Web Application!\nour application is designed to analyze and categorize URLs, identifying potential threats and classifying them into various risk levels.")
    st.title(" ")
    
    if "my_input" not in st.session_state:
      st.session_state.my_input=""
        
        
    my_input=st.text_input("Enter the URL",st.session_state.my_input)
    
    
    
    
    
    b=abnormal_url(my_input)
    if b==0:
        b=False
    else:
        b=True
    c=count_dot(my_input)
    d=count_www(my_input)
    e=count_atrate(my_input)
    f=no_of_dir(my_input)
    g=no_of_embed(my_input)
    h=shortening_service(my_input)
    i=count_https(my_input)
    j=count_http(my_input)
    k=count_per(my_input)
    l=count_ques(my_input)
    m=count_hyphen(my_input)
    n=count_equal(my_input)
    o=url_length(my_input)
    p=hostname_length(my_input)
    q=suspicious_words(my_input)
    r=digit_count(my_input)
    s=letter_count(my_input)
    t=fd_length(my_input)
    u=tld_length(get_tld(my_input,fail_silently=True))
    
    result=""
    input_data1=pd.DataFrame({"Abnormal URL":[b],"Count dot":[c],"Count WWW":[d],"Count atrate(@)":[e],"No of dir":[f]})
    input_data2=pd.DataFrame({"No of embed":[g],"Shortening Service":[h],"Count https":[i],"Count http":[j],"Count Per(%)":[k]})
    input_data3=pd.DataFrame({"Count ques(?)":[l],"Count hyphen(-)":[m],"Count equal(=)":[n],"URL Length":[o],"Hostname Length":[p]})
    input_data4=pd.DataFrame({"Suspious Words":[q],"Digit Count":[r],"Letter Count":[s],"Fd Length":[t],"Tld Length":[u]})
    
    if st.button('classify'):
        st.session_state["my_input"]=my_input
        result = pred(my_input)
        
    if result=="SAFE":
        st.success("**WEBSITE STATUS**: BENIGN")
        st.success("This URL is determined to be safe.\nIt does not appear to contain any known threats or malicious content.\n You can proceed with confidence\n")
        st.title(" ")
        st.header('CLASSIFICATION REPORT', divider='rainbow')
        st.table(input_data1)
        st.table(input_data2)
        st.table(input_data3)
        st.table(input_data4)
        
        
        
    elif result=="MALWARE":
        st.error("**WEBSITE STATUS**: MALWARE")
        st.error("**Caution**: Our system has detected potential malware associated with this URL.\nVisiting this site may pose a risk to your device and data")
        st.title(" ")
        st.header('CLASSIFICATION REPORT', divider='rainbow')
        st.table(input_data1)
        st.table(input_data2)
        st.table(input_data3)
        st.table(input_data4)
        
    elif result=="PHISHING":
        st.error("**WEBSITE STATUS**: PHISHING")
        st.error("**Warning**: This URL is flagged for potential phishing activity.\nVisiting this site may attempt to deceive you into revealing sensitive information")
        st.title(" ")
        st.header('CLASSIFICATION REPORT', divider='rainbow')
        st.table(input_data1)
        st.table(input_data2)
        st.table(input_data3)
        st.table(input_data4)
    
    
if __name__ == '__main__':
    main()

