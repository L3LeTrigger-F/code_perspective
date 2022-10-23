from dataclasses import dataclass,asdict, field
import os

@dataclass
class PersonInfo:
    person_name:str="" #作者名
    person_path:str="" #作者代码文件所在的文件夹路径
    

@dataclass
class FileFrequencyFeatureInfo:
    """
    样本的频率特征
    """
    comment_type:dict=field(default_factory=dict) #注释类型频率
    word:dict=field(default_factory=dict) #词频
    word_number_of_line:dict=field(default_factory=dict) #每行单词数量频率
    line_length:dict=field(default_factory=dict) #每行单词数据频率
    keyword:dict=field(default_factory=dict) #关键字频率
    ast_leaves:dict=field(default_factory=dict) #ast叶子节点类型频率
    identifier_length:dict=field(default_factory=dict) # 标识符长度频率
    access_control:dict=field(default_factory=dict) # 权限控制符频率
    function_length:dict=field(default_factory=dict) #函数长度频率
    function_parameter:dict=field(default_factory=dict) #函数参数个数频率
    
    
@dataclass
class FileScalarFeatureInfo:
    """
    样本的标量特征
    """
    new_usage_number:int=0 #新调用数量
    old_usage_number:int=0 #旧调用数量
    safety_usage_number:int=0 #安全调用数量
    comment_number:int=0 #注释数量
    english_number:int=0 #英语单词数量
    camel_case_number:int=0 # 驼峰命名法数量
    snake_ase_number:int=0 #蛇形命名法（下划线命名法）数量
    word_number:int=0 #总词语数量
    literal_number:int=0 #字面量数量（数值、字符串之类的）
    function_number:int=0 #函数数量
    
    blank_line_number:int=0 #空白行数量
    tab_number:int=0 #tab数量
    white_space_number:int=0 #空白字符数量
    
    tab_indent_number:int=0 #tab缩进行数量
    white_space_indent_line_number:int=0 #空格缩进行数量
    
    new_line_before_open_brance_number:int=0 #控制结构后换行数量
    on_line_before_open_brance_number:int=0 #控制结构后不换行的数量

    anonymous_function_number:int=0 #匿名函数数量
    ternary_operator_number:int=0 #三元运算符数量
    control_struct_number:int=0 #控制结构数量
    try_catch_block_number:int=0 #异常处理结构数量
    
    
@dataclass
class FileFeatureInfo:
    scalars:FileScalarFeatureInfo=FileScalarFeatureInfo()
    frequencys:FileFrequencyFeatureInfo=FileFrequencyFeatureInfo()

@dataclass
class FileRawData:
    comment:list[str]=field(default_factory=list) #注释（一个元素代表一块注释）
    variable_loc:list=field(default_factory=list) #变量位置

@dataclass
class FileInfo:
    file_name:str=""
    file_path:str=""
    file_length:int=0
    file_line_number:int=0
    
    file_features:FileFeatureInfo=FileFeatureInfo()
    file_raw_data:FileRawData=FileRawData()
    
class PersonSample:
    def __init__(self,person_info:PersonInfo,file_infos:list[FileInfo]) -> None:
        self.person_info=person_info
        self.file_infos=file_infos
    
def create_person_sample(json_data,handle)->PersonSample:
    return handle(json_data)



def parser_test(dir,instance_create_handle):
    """
    样本实例生成测试，dir为文件夹,instance_create_handle为由json->PersonSample类的实例化函数
    """
    owner_abstract={}
    files=os.listdir(dir)
    for i,f in enumerate(files):
        path=os.path.join(dir,f)
        
        with open(path,'r',encoding='utf-8') as f:
            person_sample=create_person_sample(f.read(-1),instance_create_handle)
            if person_sample is None: continue
            
            for file_info in person_sample.file_infos:
                person_name=person_sample.person_info.person_name
                if person_name not in owner_abstract:
                    owner_abstract[person_name]=[0,0]
                    
                owner_abstract[person_name][0]+=1
                owner_abstract[person_name][1]+=file_info.file_line_number
            
    print(f"包含作者个数: {len(owner_abstract)}")
    print("数据集摘要:")
    for author_name in owner_abstract:
        file_number=owner_abstract[author_name][0]
        line_number=owner_abstract[author_name][1]
        print(f'作者: {author_name} ------ 文件个数: {file_number} ------ 代码量(行): {line_number}')   
             
if __name__=="__main__":
    import json
    
    dataset_dir='test_data/cpp'
    #这个函数可以参考，运行结果的格式有一点对不上 
    def default_parse_json2person(json_data):
        def extract_freq_info(obj:dict):
                return FileFrequencyFeatureInfo(
                    comment_type=obj["CommentTypeFrequency"],
                    word=obj["wordFrequency"],
                    word_number_of_line=obj["WordNumberOfLineFrequency"],
                    line_length=obj["LineLengthFrequency"],
                    keyword=obj["keywordFrequency"],
                    ast_leaves=obj["ASTLeavesFrequency"],#这个提取不出来
                    identifier_length=obj["IndentifierLengthFrequency"],
                    access_control=obj["AccessControlFrequency"],
                    #补充两个特性
                    function_length=obj["FunctionLength"],
                    function_parameter=obj["Parameters"],
                )
                
        def extract_scalar_info(obj:dict):
            return FileScalarFeatureInfo(
                new_usage_number=obj["NewUsageNumber"],
                old_usage_number=obj["OldUseageNumber"],
                safety_usage_number=obj["SafetyUsageNumber"],
                comment_number=obj["CommentNumber"],
                word_number=obj["WordNumber"],
                ternary_operator_number=obj["TernaryOperatorNumber"],
                control_struct_number=obj["ControlStructNumber"],
                literal_number=obj["LiteralNumber"],
                blank_line_number=obj["BlankLineNumberNumber"],
                tab_indent_number=obj["TabIndentNumber"],
                new_line_before_open_brance_number=obj["NewLineBeforeOpenBranceNumber"],
                on_line_before_open_brance_number=obj["OnLineBeforeOpenBranceNumber"],
                #补充特性
                english_number=obj["EnglishNumber"],
                camel_case_number=obj["cammelIdentifierNumber"],
                snake_ase_number=obj["underScoreIdentifierNumber"],
                function_number=obj["FunctionNumber"],
                tab_number=obj["tab_num"],
                white_space_number=obj["white_space_num"],
                white_space_indent_line_number=obj["SpaceIndentNumber"],
                anonymous_function_number=obj["anonymousFunctionNumber"],
                try_catch_block_number=obj["abnormalNumber"]
            )
            
        def extract_file_info(obj:dict):
            file_features=FileFeatureInfo(
                extract_scalar_info(obj["CodeFeatures"])
                ,extract_freq_info(obj["CodeFeatures"]))
            
            return FileInfo(
                file_name=obj["FileName"],
                file_path=obj["FilePath"],
                file_length=obj["FileLength"],
                file_line_number=obj["FileLineNumber"],
                file_features=file_features
                )
            
        def extract_file_info_for_cpp(obj:dict):
            file_features=FileFeatureInfo(frequencys=extract_freq_info_for_cpp(obj["FileFeatures"]))#更改为FileFeatures
            
            return FileInfo(
                file_name=obj["PersonName"],
                file_path=obj["PersonPath"],
                file_length=obj["FileFeatures"]["FileLength"],  #更正为从json文件提取
                file_line_number=obj["FileFeatures"]["FileLineNumber"],  #更正为从json文件提取
                file_features=file_features
                )
            
        def extract_scalars_info_for_cpp(obj:dict):
            pass

        def extract_freq_info_for_cpp(obj:dict):#注释掉了，命名已更正为wordFrequency
            #obj=obj[0] 注释掉了 没有用
            if  obj is None or "wordTF" not in obj:
                return FileFrequencyFeatureInfo()
            #注释掉了，因为没有用
            #return FileFrequencyFeatureInfo(
                #comment_type={k:obj["CommentKind"][k]*100 for k in obj["CommentKind"]},
                #word={k:obj["wordTF"][k]*100 if obj["wordTF"][k]!=None else 0 for k in obj["wordTF"]}
             #   word=obj["wordTF"]
            #)
            
        obj=json.loads(json_data)
        #print(type(obj))
        extract_handle=extract_file_info
        person_info=None
        if isinstance(obj,list):
            extract_handle=extract_file_info_for_cpp
            if len(obj)==0: return None
            person_info=PersonInfo(obj[0]["PersonName"],obj[0]["PersonPath"])
            file_infos=[extract_handle(e) for e in obj]
        else:
            person_info=PersonInfo(obj["PersonName"],obj["PersonPath"])
            file_infos=[extract_handle(e) for e in obj["FileFeatures"]]




        return PersonSample(person_info,file_infos)
    
    parser_test(dataset_dir,default_parse_json2person)