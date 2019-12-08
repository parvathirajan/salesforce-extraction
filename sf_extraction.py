# -*- coding: utf-8 -*-
"""
#############################################################################################
# Script Name:		  sf_extraction.py
# Project Name:		 FOX DATA PRODUCTS
# Writen By:			Systech Solutions - Parvathirajan Natarajan
# Date Written:		 Dec 07, 2019
#
# Description:		  This script is used for extracting data from Salesforce as a Batch.
#
# Parameters:		   1) [-db] Database Name
#						2) [-sc] Schema Name
#					   2) [-sb] Is Sandbox [Yes/No] (Default 'Yes')
#					   3) [-tn] Table Name - Salesforce Table
#					   4) [-pr] Process [0 - Count_Check, 1 - Data_Extraction] (Default '0')
#
# Date Modified:		
# Modified By:			
#
# Execution example:	python sf_extraction.py -db edh -sc salesforce_sandbox -sb Yes -tn Account
#############################################################################################
"""

from __future__ import print_function
from simple_salesforce import Salesforce
from simple_salesforce import SFType
import argparse
import sys, os
import logging
from multiprocessing import Pool
import pandas
import datetime
import traceback
import signal
import pandas as pd

if sys.version_info[0] == 2:
	import ConfigParser as configparser
else:
	import configparser


def getConfig(config_file, config_item):
	"""
	Get the configuration items or credentials for the application name passed
	"""
	config = configparser.RawConfigParser()
	config.read(config_file)
	details_dict = dict(config.items(config_item))
	return details_dict
	

def chk_err(inp_str):
	"""
	for checking error
	"""
	if 'FATAL_ERROR:' in inp_str:
		# Check the status of the parents process
		check_subprocess_status()
		log_error(inp_str)
	else:
		return inp_str
	
	
def check_subprocess_status():
	"""
	for checking the process status and kill process if parent terminated
	"""
	gpid = int(os.popen("ps -p %d -oppid=" % os.getppid()).read().strip())
	ppid = int(os.getppid())
	pid = int(os.getpid())
	if gpid < 2:
		if ppid < 2:
			logging.info("Parent process has terminated, killing child process id:" + str(pid))
			os.kill(pid, signal.SIGKILL)
		else:
			logging.info("Grand Parent process has terminated, killing Parent process id:" + str(ppid) + " and Child process id:" + str(pid))
			os.kill(ppid, signal.SIGKILL)
			os.kill(pid, signal.SIGKILL)


def log_error(email_body):
	"""
	for logging Error, sending email and exiting process with error
	"""
	logging.error(email_body)
	send_mail(from_email_addr, to_email_addr, mail_subject, mail_text, files=log_file, send_cc=cc_email_addr)
	ppid = int(os.getppid())
	os.kill(ppid, signal.SIGKILL)
	sys.exit(1)


def getCurrDatetime():
	appl_datetime = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
	return appl_datetime

class SalesforceAPICall:
	"""
Used for Extracting Data from the Salesforce [Below are functions & Desc inside this Class]
	1. getConnectSF - to create the connection object with Salesforce
	2. CreateSOQL - to get the Select Statements for the Tables
	3. ExecuteSOQL is to execute the SOQL statement and return as DF
	[For Count it accepts both dict and general SOQL]
		a. If is_count = 1 & Dict as SOQL --> then return table count as Dict
		b. If is_count = 1 & General SOQL --> then return table count
	4. CreateCountDDL returns the DDL to get the table count as DF. ie., {'tbl_nm': 'select count() from tbl_nm'}
	"""
	def __init__(self, username, password, security_token=None, IsSandbox=True):
		self.username=username
		self.password=password
		self.security_token=security_token
		self.IsSandbox=IsSandbox
   
	def getConnectSF(self):
		"""
		To Autorize with the Salesforce API
		"""
		if self.security_token is None:
			return 'FATAL_ERROR: Unable to read Security Token. \nError Reason: ' + str(NameError)
		
		else:
			try:
				logging.info('Creating Connection for Salesforce...')
				self.SFObj = Salesforce(username=self.username,
							   password=self.password, 
							   security_token=self.security_token,
							   sandbox=True)
				logging.info('Connection has been created !!!')
				return self.SFObj
			except Exception as e:
				return 'FATAL_ERROR: Unable to create connection with the Salesforce. \nError Reason: ' + str(e)

  
	def CreateSOQL(self, tablename):
		"""
		Create the Select Statement for the tablename passed to this function
		"""
		if True:
			try:
				logging.info('Creating SOQL for table: ' + tablename)
				SFObj = self.getConnectSF()
				SFTypeName = SFType(tablename, SFObj.session_id, SFObj.sf_instance)
				description = SFTypeName.describe()
				field_names = [field['name'] for field in description['fields']]
				return 'SELECT {} FROM {}'.format(','.join(field_names), tablename)
			
			except Exception as e:
				return 'FATAL_ERROR: while Creating SQL \nError Reason: '+str(e)


	def ExecuteSOQL(self, SOQL, is_count=0):
		"""
		Execute SOQL with the salesforce Created SF Object
		"""
		try:
			SFObj = self.getConnectSF()
			
			if not SOQL:
				return 'FATAL_ERROR: Unable to read the Query'
			else:
				logging.info('Executing SQL to Get the table {}...'.format('Data' if is_count==0 else 'Count'))
				if is_count == 1:
					if type(SOQL) == dict:
						for tablename, count_soql in SOQL.items():
							result = SFObj.query_all(count_soql)
							count = list(result.items())[0][1]
							SOQL[tablename] = count
						return SOQL
					else:
						result = SFObj.query_all(SOQL)
						count = list(result.items())[0][1]
						return count
				else:
					results = SFObj.query_all(SOQL)
					sf_df = pd.DataFrame(results['records']).drop(columns='attributes')
					print(sf_df)
					return sf_df
				
		except Exception as e:
			return 'FATAL_ERROR: while executing SQL \nError Reason: '+str(e)


	def CreateCountDDL(self, *args, tablenames=None):
		ddl_dict = dict()
		if tablenames is not None or args is not None:
			print('Table Namelist or Args present')
			if type(tablenames)==list or type(tablenames)==tuple:
				print('Tablelist')
				for table in tablenames:
					soql = "SELECT COUNT() FROM {}".format(table)
					ddl_dict[table] = soql
			elif len(args)>1:
				print('Args Tablelist')
				print(args)
				for table in args:
					soql = "SELECT COUNT() FROM {}".format(table)
					ddl_dict[table] = soql
			elif len(args)==1:
				soql = "SELECT COUNT() FROM {}".format(args[0])
				ddl_dict = soql
				
			return ddl_dict
		else:
			return "FATAL_ERROR: Cannot parse 'Nonetype' as Table Names"



def getRecordCount(table_name):
	"""
	TO get the Record Count for the tables
	"""
	if type(table_name) == list or type(table_name) == tuple:
		count_check_sql = SFAPI.CreateCountDDL(tablenames=table_name)
		rec_count = SFAPI.ExecuteSOQL(count_check_sql, is_count = 1)
		print(rec_count)
		return rec_count
	else:
		print('Inside the Record Count Function for Single table')
		print(SFAPI)
		count_check_sql = SFAPI.CreateCountDDL(table_name)
		rec_count = SFAPI.ExecuteSOQL(count_check_sql, is_count = 1)
		print(rec_count)
		return rec_count
		
		
def ExtractData(table_name):
	"""
	Extracts Data from the Salesforce
	"""
	logging.info('Extract Data for Table Name: ' + table_name + ' at ' + getCurrDatetime())
	try:
		rec_count = getRecordCount(table_name)
		print(rec_count)
		if int(rec_count) == 0:
			logging.info('There is no data to Extract for {}'.format(table_name))
		else:
			soql = SFAPI.CreateSOQL(table_name)
			data = SFAPI.ExecuteSOQL(soql, is_count=0)
			extract_file_nm = table_name + '_' + db_name + '_'  + sc_name + '_' + curr_datetime + '.csv'
			print(data)
			print(type(data))
			extract_file = os.path.expanduser(os.path.join(script_path,extract_file_nm))
			data.to_csv(extract_file, index=False)
			logging.info('Data has been extrcated as {} at {}'.format(extract_file, getCurrDatetime()))
			
	except Exception as e:
		logging.info('Error in Extraction')
		err_msg = "FATAL_ERROR: In the ExtractData Function : {0}\n\n{1}".format(e, traceback.format_exc())
		raise Exception(str(err_msg))


#################################################
############--Start of Main module--#############
#################################################

if __name__ == '__main__':
	try:
		# Parsing Input Arguments
		parser = argparse.ArgumentParser(description = 'SF Extraction Process')
		parser.add_argument("-db", action="store", dest="db_name", help="DataBase Name to Load Data", required=False, default="edh")
		parser.add_argument("-sc", action="store", dest="sc_name", help="Schema Name to Load Data", required=False, default="salesforce_sandbox")
		parser.add_argument("-sb", action='store', dest='is_sbox', help='Is this Sandbox?', required=False, default='Yes')
		parser.add_argument('-tn', action='store', dest='table_name', help='Table(s) to process', nargs='+', required=False, default=None)
		parser.add_argument('-pr', action='store', dest='process_nm', help='Type of the Process [Either count_check or data_extraction]', nargs='+', required=False, default=None)
		args = parser.parse_args()
		
		# Assigning Input Arguments
		db_name = args.db_name
		sc_name = args.sc_name
		is_sbox = args.is_sbox.lower()
		table_name = args.table_name
		process_nm = args.process_nm
		
		# Script Arguments
		if 'yes' in is_sbox:
			is_sbox = True
		else:
			is_sbox = False
		
		# Parallel Process Count
		processes = 10
		
		scriptnm = 'sf_extraction'
		mail_subject = 'Error While executing script ' + scriptnm
		
		#Required Script Variables from the Configuration file
		script_path = os.path.abspath(os.path.dirname(__file__))
		config_file = (os.path.expanduser(os.path.join(script_path,'.'+scriptnm+'.cfg')))
		print(config_file)
		config = getConfig(config_file, 'salesforce-foxp2p1dat')

		username	= config['username']
		password	= config['password']
		sf_token	= config['sf_token']
		
		curr_datetime = str(datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
		
		log_file_nm = '{}_{}_{}.log'.format(scriptnm, db_name, curr_datetime)
		log_file = os.path.expanduser(os.path.join(script_path,log_file_nm))
		
		logging.basicConfig(filename=log_file, format='%(asctime)s:%(msecs)09d %(filename)s (%(lineno)d) %(levelname)s   : %(message)s', datefmt='%Y%m%d:%H:%M:%S', level=logging.INFO)
		
		print(log_file)
		
		logging.info('Application Starts at : {}'.format(getCurrDatetime()))
		logging.info('Application Args:\nDatabase: ' + db_name + '\nSchema Name: ' + sc_name + '\nIs Sandbox: ' + str(is_sbox))
		
		logging.info('Creating Object for Salesforce API Call...')
		
		global SFAPI
		
		SFAPI = SalesforceAPICall(username=config['username'],
							password=config['password'],
							security_token=config['sf_token'],
							)
		
		print(SFAPI)
		
		if len(table_name) != 0 and 'data_extraction' in process_nm:
			"""send the list of dictionaries as argument list for pool map function for multiprocessing """

			try: 
				if len(table_name) == 1:
					print(table_name[0])
					ExtractData(table_name[0])
				if type(table_name) == list and len(table_name) > 1:
					#p = Pool(processes=int(processes))
					print('Calling Pool : ' + str(os.cpu_count()))
					#out = p.map(ExtractData, table_name)
					#p.close()
					#p.join()
					p = Pool()
					print(table_name)
					x = p.map(ExtractData, table_name)
					x.get()
					p.close()
					p.join()
			except Exception as e:
				if len(table_name) > 1:
					p.terminate()
					p.join()
				logging.error("Process Failed - " + str(e))
				mail_text = "Salesforce Data Extraction script failed - Database: {}. Error Reason: {}".format(db_name, str(e))
				mail_subject = "Salesforce Data Extraction script failed - Database: {}. Error Reason: {}".format(db_name, str(e))
				raise Exception(e)
					
		elif len(table_name) != 0 and 'count_check' in process_nm:
			rec_count = getRecordCount(table_name)
			print(rec_count)
		
		elif len(table_name) >0 and process_nm is None:
			logging.info('Process Name should be passed to choose the Script process, either data_extraction or count_check')
			chk_err('FATAL_ERROR: Process Name should be passed - [data_extraction or count_check]')
			
		else:
			logging.info("Table Names Should be passed to Extract Data or to get the Record Count")
			
		
	except Exception as e:
		chk_err('FATAL_ERROR: ' + " from main exception : {0}\n\n{1}".format(e, traceback.format_exc()))
