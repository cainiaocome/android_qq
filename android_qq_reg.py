#!/usr/bin/env python2.7
# encoding: utf8

import os
from appium import webdriver
import time
import random
import traceback


desired_caps = {
                 'platformName':'Android',
                 'platforVersion':'5.0',
                 'deviceName':'xiaominote-3',
                 'appPackage':'com.tencent.mobileqq',
                 'appActivity':'com.tencent.mobileqq.activity.SplashActivity',
                 #'appActivity':'com.tencent.mobileqq.activity.AccountManageActivity',
               }
driver = webdriver.Remote('http://127.0.0.1:4723/wd/hub', desired_caps)

time.sleep(3)

try:
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
    input_mobile_number.send_keys( '1326968{}'.format(random.randint(1000,9999)) )
    time.sleep(3)

    button_next_step = driver.find_element_by_name(ur'下一步')
    button_next_step.click()
    time.sleep(3)

    input_vcode = driver.find_element_by_name(ur'请输入短信验证码')
    input_vcode.send_keys( '000000')
    time.sleep(3)

    try:
        checkbox_bind_mobile = driver.find_element_by_xpath(
                    ur'//android.widget.CheckBox[@content-desc="将此手机号与QQ绑定，提高帐号安全性"]')
        print 'bind mobile selected'
        checkbox_bind_mobile.click()
        time.sleep(1)
    except:
        pass
    try:
        checkbox_device_lock = driver.find_element_by_name(ur'//android.widget.CheckBox[@content-desc="开启设备锁，保障QQ帐号安全"]')
        print 'device lock selected'
        checkbox_device_lock.click()
        time.sleep(1)
    except:
        pass

    button_next_step = driver.find_element_by_name(ur'下一步')
    button_next_step.click()
    time.sleep(3)
except:
    traceback.print_exc()
    pass

driver.quit()
