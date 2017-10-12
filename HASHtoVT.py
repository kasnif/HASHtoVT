#!/usr/bin/env python
# -*- coding: utf-8 -*-

# USED Python 2.7

import hashlib
import glob
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
from datetime import datetime

filetime = datetime.now().strftime("%Y%m%d-%H%M%S")
filelist = glob.glob('.\\*') #調査対象フォルダ（指定可能）
log = open('.\\'+filetime+'HASHtoVT.py.log','w',)#ログ保存フォルダ（指定可能）
driverpath='C:\\py\\chromedriver'#Chromeドライバのパス（環境に合わせて要変更）Get form https://sites.google.com/a/chromium.org/chromedriver/downloads

maxlist = len(filelist)
isdir=0
files=[]
iigus=0

while 1:
        if os.path.isfile(filelist[isdir]) is True:
                if "HASHtoVT.py" not in filelist[isdir]:
                        files.append(filelist[isdir])
                        iigus+=1
        isdir+=1
        if isdir is maxlist: break

maxfiles = len(files)
num=0

while 1:
        time.sleep(5)
        f = open(files[num], 'rb')
        data = hashlib.sha256()
        while 1:
                x = f.read(16384)
                if not x: break
                data.update(x)
        print("[File Infomation]")
        print >> log, ("\n\n-------------------------------\n[File Infomation]")
        print data.hexdigest()+" "+files[num]
        log.write(data.hexdigest()+" "+files[num]+'\n')

        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        driver = webdriver.Chrome(executable_path=driverpath,chrome_options=options)

        url = 'https://www.virustotal.com/#/file/'+data.hexdigest()

        driver.get(url)
        time.sleep(5)

        if "McAfee" in driver.page_source.encode('utf-8','replace') or "AhnLab-V3" in driver.page_source.encode('utf-8','replace') or "Malwarebytes" in driver.page_source.encode('utf-8','replace'):
                print("[Detection]")
                vender = driver.find_elements_by_xpath('//p/span[@class="engine-name style-scope vt-detections"]')
                detect = driver.find_elements_by_xpath('//p/span[@class="individual_detection style-scope vt-detections"]')
                max1 = len(vender)
                num1=0
                print >> log, ("[Detection]")
                while 1:
                        print >> log, ("%-24s:%s" % (vender[num1].text,detect[num1].text))
                        num1+=1
                        if num1 is max1: break
                        
                if "Basic Properties" in driver.page_source.encode('utf-8','replace'):
                        link = driver.find_element_by_link_text("Details")
                        link.click()
                        print("[Details]")
                        detailfield = driver.find_elements_by_xpath('//div[@class="th style-scope vt-keyval-table"]')
                        detailinfo = driver.find_elements_by_xpath('//div[@class="td style-scope vt-keyval-table"]')
                        max2 = len(detailfield)
                        num2=0
                        print >> log, ("[Details]")
                        while 1:
                                ans1 = detailfield[num2].text.encode('utf-8','replace')
                                ans2 = detailinfo[num2].text.encode('utf-8','replace')
                                print >> log, ("%-24s:%s" % (ans1,ans2))
                                num2+=1
                                if num2 is max2: break
                else:
                        print("[Details is not exist]")
                        print >> log, ("[Details is not exist]")


                if "File system actions" in driver.page_source.encode('utf-8','replace') or "Network Communication" in driver.page_source.encode('utf-8','replace') or "Process and service actions" in driver.page_source.encode('utf-8','replace') or "Modules loaded" in driver.page_source.encode('utf-8','replace'):
                        link = driver.find_element_by_link_text("Behavior")
                        link.click()
                        print("[Behavior]")
                        Behavfield = driver.find_elements_by_xpath('//div[@class="details style-scope vt-expandable-subsection"]')
                        max3 = len(Behavfield)
                        num3=0
                        print >> log, ("[Behavior]")
                        while 1:
                                ansB1 = Behavfield[num3].text.encode('utf-8','replace')
                                print >> log, (ansB1)
                                num3+=1
                                if num3 is max3: break
                else:
                        print("[Behavior is not exist]")
                        print >> log, ("[Behavior is not exist]")

        else:
                print >> log, ("[This file is No Information]")
                print ("[This file is No Information]")

        driver.close()
        num+=1
        f.close()
        time.sleep(10)

        if num is maxfiles: break

log.close
print "end"
