#!/usr/bin/env python2.7
# encoding: utf8

import os
from appium import webdriver
import time


desired_caps = {
                 'platformName':'Android',
                 'platforVersion':'5.0',
                 'deviceName':'xiaominote-3',
                 'appPackage':'com.tencent.mobileqq',
                 'appActivity':'com.tencent.mobileqq.activity.SplashActivity',
                 #'appActivity':'com.tencent.mobileqq.activity.AccountManageActivity',
               }
driver = webdriver.Remote('http://127.0.0.1:4723/wd/hub', desired_caps)

time.sleep(7)

button_head = driver.find_element_by_id('com.tencent.mobileqq:id/conversation_head')
button_head.click()
time.sleep(3)

button_settings = driver.find_element_by_id('com.tencent.mobileqq:id/settings')
button_settings.click()
time.sleep(3)

button_settings = driver.find_element_by_id('com.tencent.mobileqq:id/account_switch')
button_settings.click()
time.sleep(3)

button_settings = driver.find_element_by_id('com.tencent.mobileqq:id/new_account')
button_settings.click()
time.sleep(3)

button_new_account = driver.find_element_by_name(ur'新用户')
button_new_account.click()
time.sleep(3)

input_mobile_number = driver.find_element_by_name(ur'请输入你的手机号码')
input_mobile_number.send_keys('13269682231')
time.sleep(3)

button_next_step = driver.find_element_by_name(ur'下一步')
button_next_step.click()
time.sleep(3)
