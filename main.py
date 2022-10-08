from feature import FileParse
import os
import csv
import re
import time
from feature import AllFeatures
import json
def main():
    authorinfo = {
        'newUsageNumber': 0,
        'oldUsageNumber': 0,
        'safetyUsageNumber': 0,
        'unsafetyUsageNumber': 0,
        'externFunctionNumber': 0,
        'commentNumber': 0,
        'codeLength': 0,
        'longFunctionNumber': 0,
        'Functionavg': 0,
        'Functionstd':0,
        'functionNumber': 0,
        'variableVariance': 0,
        'englishScore': 0,
        'englishUsageTime': 0,
        'macroNumber': 0,
        'identifierNumber': 0,
        'lambdaNumber': 0,
        'inlineNumber': 0,
        'virtualNumber': 0,
        'TemplateNumber': 0,
        'staticNumber': 0,
        'ExternNumber': 0,
        'PointerFunc': 0,
        'PointerVar': 0,
        'newNumber': 0,
        'deleteNumber': 0,
        'normalNumber':0,
        'llen':0
    }
    #Datadir为当前存放数据集的文件夹名称
    Datadir = './resources'
    file_error='data_error.txt'
    fr=open('./data_err.csv','w',encoding='utf-8')
    #file_name="five_data.csv"
    #f=open(file_name,'r',encoding="utf-8")
    #csv_writer = csv.writer(f)
    '''
    f=open('./five_data.csv', 'w', encoding='utf-8')
    csv_writer = csv.writer(f)
    csv_writer.writerow(["name", "openness", "conscientiousness", "extroversion", "agreeableness", "neuroticism"])
    f1=open('./five_data_all.csv', 'w', encoding='utf-8')
    csv_writer_1 = csv.writer(f1)
    csv_writer_1.writerow(["name", "openness", "conscientiousness", "extroversion", "agreeableness", "neuroticism"])
    f2=open('./five_data_single.csv','w',encoding='utf-8')
    csv_writer_2=csv.writer(f2)
    csv_writer_2.writerow(["name", "openness", "conscientiousness", "extroversion", "agreeableness", "neuroticism"])
    fr=open('./data_err.csv','w',encoding='utf-8')
    '''
    for dir in os.listdir(Datadir):
        Author = dir
        content = []
        #Author为作者名称，在之前Java的数据集中，数据保存形式为以作者命名的文件夹下包含作者的代码
        value_info={
        'openness':0,
        'conscientiousness':0,
        'extroversion':0,
        'agreeableness':0,
        'neuroticism':0
    }
        ll=0
        file_list = []
        for dirpath, dirname, files in os.walk(Datadir + '/' + dir):
            print(dirpath)
            for file in files:
                forbidfile=r"csv"
                if re.findall(forbidfile,file)!=[]:
                    continue
                ll+=1
                file_path = os.path.join(dirpath, file)
                if "\\" in file_path:
                    file_path = file_path.replace('\\', '/')
                file_list.append(file_path)
        st_all=time.time()
        #print(file_list)
        for file in file_list:
            try:
                start_time=time.time()
                parser = FileParse.FileParser()
                print(file)
                author_info_1=parser.parse(file)
                #author_info_1['file']=file
                content.append(author_info_1)
                #csv_writer_2.writerow([file,openn,consc,extro,agree,neuro])
                #f2.flush()
                #if openn!=None:
                 #   value_info['openness']+=openn
                #if consc!=None:
                 #   value_info['conscientiousness'] += consc
                #if extro!=None:
                 #   value_info['extroversion']+=extro
                #if agree!=None:
                 #   value_info['agreeableness']+=agree
                #if neuro!=None:
                 #   value_info['neuroticism']+=neuro
                #print(openn, consc, extro, agree, neuro)
                #for key in authorinfo:
                 #   authorinfo[key]+=author_info_1[key]
                #print(value_info)
            except:
                fr = open(file_error, 'w', encoding='utf-8')
                fr.write(file)
                fr.flush()
        with open(Author+'.json',mode='w',encoding='utf-8') as f:
            for each_dict in content:
                f.write(json.dumps(each_dict)+'\n')
        print("提取作者所有代码特征时间为：",time.time()-st_all)
        #authorinfo['llen']=ll
        #print([Author,value_info['openness']/float(ll),value_info['conscientiousness']/float(ll),value_info['extroversion']/float(ll),value_info['agreeableness']/float(ll),value_info['neuroticism']/float(ll)])
        #if ll!=0:
            #csv_writer.writerow([Author,value_info['openness']/float(ll),value_info['conscientiousness']/float(ll),value_info['extroversion']/float(ll),value_info['agreeableness']/float(ll),value_info['neuroticism']/float(ll)])
        #f.flush()
        #all_file = AllFeatures.global_info(**authorinfo)
        #openness, conscientiousness, extroversion, agreeableness, neuroticism = all_file.parse()
        #print("another way")
        #print(openness, conscientiousness, extroversion, agreeableness, neuroticism)
        #csv_writer_1.writerow([Author,openness,conscientiousness,extroversion,agreeableness,neuroticism])
        #f1.flush()
    fr.close()

if __name__ == '__main__':
    main()


