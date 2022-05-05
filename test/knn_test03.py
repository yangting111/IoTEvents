# -*- coding: UTF-8 -*-
import numpy as np
import operator
import os
from os import listdir
from sklearn.neighbors import KNeighborsClassifier as kNN
import pandas as pd

"""
函数说明:将32x32的二进制图像转换为1x1024向量。

Parameters:
    filename - 文件名
Returns:
    returnVect - 返回的二进制图像的1x1024向量

Modify:
    2017-07-15
"""

UCI_MLD_REF_MSG = ("The example data could not be found. You need to download the Robot Execution Failures "
                   "LP1 Data Set from the UCI Machine Learning Repository. To do so, you can call the function "
                   "tsfresh.examples.robot_execution_failures.download_robot_execution_failures")
data_file_name="11_28write_data.txt"
test_file_name="12_02write_data.txt"

"""
函数说明:手写数字分类测试

Parameters:
    无
Returns:
    无

Modify:
    2017-07-15
"""
def processData(dataLenList,lableList,n):

    processdata=dataLenList[n]
    processlable=lableList[n]
    mtrain=len(processdata)
    trainingMat = np.zeros((mtrain, n))
    for i in range(mtrain):
        trainingMat[i, :] =processdata[i]
    return trainingMat,processlable

def trainingData(trainingMat,hwLabels,test_dateMat,testLable):

    #构建kNN分类器
    neigh = kNN(n_neighbors =1, algorithm = 'auto')
    #拟合模型, trainingMat为测试矩阵,hwLabels为对应的标签
    neigh.fit(trainingMat, hwLabels)
    #错误检测计数
    errorCount = 0.0
    #测试数据的数量
    mTest = len(test_dateMat)
    #从文件中解析出测试集的类别并进行分类测试
    for i in range(mTest):
        # classifierResult = neigh.predict(test_dateMat)
        # print("分类返回结果为%s\t真实结果为%s" % (classifierResult, testLable))
        classifierResult = neigh.predict([test_dateMat[i]])
        print("分类返回结果为%s\t真实结果为%s" % (classifierResult[0], testLable[i]))
        if(str(classifierResult[0]) != str(testLable[i])):
            errorCount += 1.0
    print("%d 总共错了%d个数据\n错误率为%f%%" % (len(test_dateMat[0]),errorCount, errorCount/mTest * 100))
    return  errorCount,mTest
"""
函数说明:load_flow_data函数

Parameters:
    multiclass 设置
Returns:
    

Modify:
    2017-07-15
"""
def load_flow_data(data_file_name):

    if not os.path.exists(data_file_name):
        raise RuntimeError(UCI_MLD_REF_MSG)
    id_to_target = {}
    df_rows = []
    dataLenList = {}
    lableList = {}
    with open(data_file_name) as f:
        cur_id = 0
        values = []
        for line in f.readlines():
            # New sample --> increase id, reset time and determine target
            if line[0] not in ['\t', '\n']:
                if True:
                    id_to_target[cur_id] = line.strip()
                else:
                    id_to_target[cur_id] = (line.strip() == 'normal')
                cur_id += 1
                df_rows.append(values)
                values = []
            # Data row --> split and convert values, create complete df row
            elif line[0] == '\t':
                if int(line.split('\t')[3])==1:
                    values.append(line.split('\t')[4])
                elif int(line.split('\t')[3])==0:
                    tmp=-int(line.split('\t')[4])
                    values.append(str(tmp))
    m = len(df_rows)
    for i in range(m):
        dataLen = len(df_rows[i])
        if dataLen in dataLenList:
            dataLenList[dataLen].append(df_rows[i])
            lableList[dataLen].append(id_to_target[i])
        else:
            dataLenList[dataLen]=[]
            lableList[dataLen]=[]
            dataLenList[dataLen].append(df_rows[i])
            lableList[dataLen].append(id_to_target[i])
    return dataLenList, lableList
"""
函数说明:main函数

Parameters:
    无
Returns:
    无

Modify:
    2017-07-15
"""

if __name__ == '__main__':
    errorall=0
    totall=0
    data,lable =load_flow_data(data_file_name)
    test_date, test_lable = load_flow_data(test_file_name)
for i in test_date.keys():
    if i in data.keys():
        dateMat, lableList = processData(data, lable, i)
        test_dateMat, test_lableList = processData(test_date,test_lable,i)
        ecount,mtest=trainingData(dateMat,lableList,test_dateMat,test_lableList)
        errorall=errorall+ecount
        totall=totall+mtest
    else:
        errorall=errorall+len(test_date[i])
        totall=totall+len(test_date[i])
print("总共错了%d个数据\n错误率为%f%%" % (errorall, errorall/totall * 100))

