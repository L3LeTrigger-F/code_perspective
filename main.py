from calendar import c
from feature import FileParse
import os
import csv
import re
import time
from feature import AllFeatures
import json
import tqdm
def main():
    #存储全部信息
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
    #Datadir为当前存放数据集的文件夹名称s
    #Datadir = '../MaliciousCode/authors'
    Datadir='/home/codedataset/CodePerspective-cpp/data1'
    file_error='data_error.txt'
    fr=open(file_error,'w',encoding='utf-8')
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

    run_dirs=[]
    for dirs in os.listdir('./data'):
        run_dirs.append(dirs)
    for dir in os.listdir(Datadir):
        if dir in run_dirs:
            print(dir)
            #continue
                #Author为作者名称
        Author = dir
        paths="./data/"+dir+"/"
        if not os.path.exists(paths):
            os.makedirs(paths)
        content = []
        #大五人格信息，现在暂不考虑
        value_info={
        'openness':0,
        'conscientiousness':0,
        'extroversion':0,
        'agreeableness':0,
        'neuroticism':0
        }
        ll=0
        file_list = []
        #一种读取逻辑
        for dirpath, dirname, files in os.walk(Datadir + '/' + dir):
            for dirs in dirname:
                if dirs=='C++':
                    for dirpaths,dirnames,filess in os.walk(Datadir+'/'+dir+'/'+dirs):
                        for fi in filess:
                            file_path = os.path.join(dirpath+'/'+dirs, fi)
                            if "\\" in file_path:
                                file_path = file_path.replace('\\', '/')
                            file_list.append(file_path)
        #另一种读取逻辑
            #for file in files:
             #   forbidfile=r"csv"
              #  if re.findall(forbidfile,file)!=[]:
               #     continue
                #ll+=1
                #file_path = os.path.join(dirpath, file)
                #if "\\" in file_path:
                 #   file_path = file_path.replace('\\', '/')
                #file_list.append(file_path)
        st_all=time.time()
        author_info=[]
        for file in file_list:
            try:
                parser = FileParse.FileParser()
                print("---"+file+"---")
                author_info_1=parser.parse(file)
                file_info={"PersonName":Author,"PersonPath":file,"FileFeatures":author_info_1}
                author_info.append(file_info)
                #print(author_info_1)
                #author_info_1['file']=file
                #content.append(author_info_1)
                #deal_name=file[file.find("C++/")+4:file.find(".cpp")]ss
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
        dats=json.dumps(author_info,ensure_ascii=False,indent=1)
        with open("./test_data/"+"cpp/"+Author+".json",'w',newline='\n',encoding='utf-8') as f:
            f.write(dats)
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
    print("finished!!!")
if __name__ == '__main__':
    main()
