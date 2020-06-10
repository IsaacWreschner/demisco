import requests

#global const variables
API_KEY = 'eb81632be4fea778fef9cca64ee1b4f601191cbd4eb33effdcf184ee7eb437d7'
URL = 'https://www.virustotal.com/vtapi/v2/file/report'


class MarkDownTableGenerator:
    def __init__(self,columns):
        self.columns = columns
        self.matrix = []
        
    #public methods
    def generate(self):
        markDown = self.__generateHeader()
        for row in self.matrix:
            markDown+=self.__generateRow(row)
            markDown+= '\n'
        return markDown

    def addRow(self,row):
        # this class is implemented for this specific project and not
        # for global use, so i don't except a user will insert a wrong ROW parameter
        self.matrix.append(row)
        
    # "private" methods
    def __generateHeader(self):
         markDown = self.__generateRow(self.columns) + '\n'
         emptyRow = ['---' for i in range(len(self.columns))]
         markDown+= self.__generateRow(emptyRow) + '\n'
         return markDown
    
    def __generateRow(self,row):
        markDown = '|'
        for cell in row:
           markDown+=cell
           markDown+='|'    
        return markDown


def MarkDownHeaderGenerator(level,text):
    if level > 6:
        return ''
    markDown = ''
    for i in range(level):
        markDown+= '# '
    markDown+= text + '\n'
    return markDown


def createScannedFileTable(res):
    markDown = MarkDownHeaderGenerator(1,'Scanned File')
    tableGenerator = MarkDownTableGenerator(['MD-5','SHA-1','SHA-256'])
    #default data
    md5,sha1,sha256 = 'data unavailable','data unavailable','data unavailable'
    if "md5" in res:
        md5 = res["md5"]
    if "sha1" in res:
        sha1 = res["sha1"] 
    if "sha256" in res:
        sha256 = res["sha256"]
    tableGenerator.addRow([md5,sha1,sha256])
    markDown+= tableGenerator.generate()
    return  markDown 


def createResultsTable(res):
    markDown = MarkDownHeaderGenerator(1,'Results')
    tableGenerator = MarkDownTableGenerator(['Total Scans','Positive Scans'])
    #default data
    total,positives = 'data unavailable','data unavailable'
    if "total" in res:
        total = str(res["total"])
    if "positives" in res:
        positives = str(res["positives"])
    tableGenerator.addRow([total,positives])
    markDown+= tableGenerator.generate()
    return  markDown 


def createScansTable(res):
    markDown = MarkDownHeaderGenerator(1,'Scans')
    #prevent future potential errors
    if "scans" not in res or type(res["scans"]) is not dict:
        markDown+='no data available'
        return markDown
    tableGenerator = MarkDownTableGenerator(['Scan Origin ','Scan Result '])
    for scan in res["scans"].items():
        tableGenerator.addRow(createScansRow(scan))
    markDown+= tableGenerator.generate()
    return  markDown 


def createScansRow(scan):
    origin = str(scan[0])
    result = 'data unavailable'
    if "result" in scan[1]:
        result = str(scan[1]["result"])
    return [origin,result]


def main(resource):
    #initialize params
    params = {'apikey': API_KEY, 'resource': resource}
    try:
       response = requests.get(URL, params=params)
    except:
        return '# error \n an error occurred during the request'
    
    if(response.status_code is not 200):
        return '# no data \n virus total responded with a '+ str(response.status_code)+' status code.'
    #if status code is 200
    res = response.json()
    markDown = createScannedFileTable(res)
    markDown+=createResultsTable(res)
    markDown+=createScansTable(res)
    return markDown



