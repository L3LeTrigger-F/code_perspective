import json
import re
import numpy as np
import time
from antlr4 import *
from src.spam.parser.CPPExtract import CPP14Extract
from src.spam.parser.sa_cpp14 import *
import spam
import math
import chardet
class ExampleErrorListener(SA_ErrorListener):
    def syntaxError(self, input_stream, offendingSymbol,
        char_index:int, line:int, column:int, msg:str
    ):
        print("Syntax Error!")
        print("    input_stream:", repr(input_stream))
        print("    offendingSymbol:", offendingSymbol, type(offendingSymbol))
        print("    char_index:", char_index)
        print("    line:", line)
        print("    column:", column)
        print("    msg:", msg)

class FileParser():
    def __init__(self):
        self.listener = CPP14Extract()
        self.walker = ParseTreeWalker()
        self.tokenNum=0
        self.maxdepth=0
        self.authorinfo = {
            'newUsageNumber': 0,
            'oldUsageNumber': 0,
            'safetyUsageNumber': 0,
            'unsafetyUsageNumber': 0,
            'externFunctionNumber': 0,
            'commentNumber': 0,
            'codeLength': 0,
            'longFunctionNumber': 0,
            'functionNumber': 0,
            'variableVariance': 0,
            'englishScore': 0,
            'englishUsageTime': 0,
            'preprocessNumber': 0,
            'identifierNumber': 0,
            'lambdaNumber': 0,
            'inlineNumber': 0,
            'virtualNumber': 0,
            'TemplateNumber': 0,
            'staticNumber': 0,
            'ExternNumber': 0,
            'PointerFunc': 0,
            'PointerVar': 0,
            'normalNumber':0,
            'newNumber': 0,
            'deleteNumber': 0,
        }
        self.funcLength=[]
    #这里有问题，需要处理tokens
    def calculatewordTF(self,token):
        code_dict=dict.fromkeys(token,0)
        for word in token:
            code_dict[word]+=1
        for keys in code_dict:
            code_dict[keys]/=len(token)
        #print(code_dict)
        return code_dict
    def calaulateUsage(self, code):
        #以C++17为标准
        rules_new = [
            r"#include<Filesystem>",r"apply\((.*?)\)",r"invoke\((.*?)\)",r"optional<(.*?)>",
            r"#include<any>",r"#include<variant>",r"#include<string_new>",r"scoped_lock",
            r"make_from_tuple",r"charconv",r"search\((.*?)\)",
            r"default_searcher",r"boyer_moore_searcher",r"boyer_moore_horspool_searcher",
            r"execution",r"memory_resource",r"if constexpr",r"u8'(.*?)'",r"\[\[fallthrough\]\]",
            r"\[\[nodiscard\]\]",r"\[\[maybe_unused\]\]",r"__has_include",r"static_assert",r"template<template<typename",
            r"namespace (.*?)::(.*?)::"
        ]
        # abandon usage
        rules_old = [
            r"std::auto_ptr",r"register",r"unexpected_handler",r"set_unexpected\((.*?)\)",r"convert_type",
            r"<ccomplex>",r"<cstdalign>",r"<cstdbool>",r"<ctgmath>",r"gets\(\)",r"throw\((.*?)\)",r"trigraph",r"static constexpr",
            r"random_shuffle",r"allocator<void>",r"<codecvt>",r"raw_storage_iterator",r"get_temporary_buffer",r"is_literal_type",
            r"std::iterator",r"memory_order_consume",r"shared_ptr::unique",r"result_of"
        ]
        # safety usage
        rules_safety = [
            r"fgets",r"gets_s",r"strncpy",r"strcpy_s",r"strncat",r"strcat_s",r"snprintf",r"_snprintf_s",
            r"_snwprintf_s",r"vsnprintf",r"strtol",r"strtoll",r"strtof",r"strtod",r"strncpy",r"strlcpy",r"strcpy_s",
            r"strncat",r"strlcat",r"strcat_s",r"strtok",r"snprintf",r"vsnprintf",r"_makepath_s",r"_splitpath_s",
            r"_splitpath_s",r"_snscanf_s",r"strnlen_s"
        ]
        rules_unsafety=[
            r"gets",r"strcpy",r"strcat",r"sprintf",r"scanf",r"sscanf",r"fscanf",r"vfscanf",r"vsprintf",r"vsscanf",
            r"stread",r"strecpy",r"strtrns",r"realpath",r"syslog",r"getopt",r"getopt_long",r"getpass",r"getchar",
            r"fgetc",r"getc",r"read",r"bcopy",r"memcpy",r"snprintf",r"strccpy",r"strcadd",r"atoi",r"atol",r"atoll",
            r"stof",r"strcpy",r"strcat",r"sprintf",r"vsprintf",r"makepath",r"_splitpath",r"scanf",r"sscanf",r"snscanf",
            r"strlen"
        ]
        new_list=[re.findall(rule, str(code)) for rule in rules_new]
        newUsageNumber = sum([len(re.findall(rule, str(code))) for rule in rules_new])
        oldUsageNumber = sum([len(re.findall(rule, str(code))) for rule in rules_old])
        safetyUsageNumber = sum([len(re.findall(rule, str(code))) for rule in rules_safety])
        unsafetyUsageNumber=sum([len(re.findall(rule, str(code))) for rule in rules_unsafety])
        newUsageRate=newUsageNumber / (newUsageNumber + oldUsageNumber) if newUsageNumber + oldUsageNumber != 0 else None
        safeteUsageRate=safetyUsageNumber/(safetyUsageNumber+unsafetyUsageNumber) if safetyUsageNumber+unsafetyUsageNumber!=0 else None
        self.authorinfo['newUsageNumber']+=newUsageNumber
        self.authorinfo['oldUsageNumber']+=oldUsageNumber
        self.authorinfo['safetyUsageNumber']+=safetyUsageNumber
        self.authorinfo['unsafetyUsageNumber']+=unsafetyUsageNumber
        return newUsageRate,safeteUsageRate
 #C++字符串形式更改，正则表达式 字符串夹杂变量是否考虑？
    def extractStringOutput(self, code):
        rules=[
        r'std::cout<<'
          r'cout<<"(.*?)"',
          r'printf[(]""(.*?)"(.*?)[)]',
          r'throw "(.*?)"',
          r'return "(.*?)"',
          r'cerr<<"(.*?)"'
        ]
        stringOutput = []
        for rule in rules:
            stringOutput.extend(re.findall(rule, code))
        return stringOutput
    def extractExternFunction(self,code):#正则匹配法
        extern_rules=r'extern(.*?)\((.*?)\)'
        self.listener.externFunctionNumber+=sum([len(re.findall(extern_rules, str(code)))])
        #self.authorinfo['externFunctionNumber']+=sum([len(re.findall(extern_rules, str(code)))])
    def extractComment(selfself,file):
        CommentList=[]
        Block_op=False
        for line in file:
            if Block_op==True:
                if line.find('*/')!=-1:
                    if line.find('*/')!=-1:
                        CommentList.append(line[:line.find('*/')])
                    Block_op=False
                else:
                    CommentList.append(line[line.find('/*')+2:])
            if line.find('//')!=-1:
                CommentList.append(line[line.find('//')+2:])
            if line.find('/*')!=-1 and line.find('*/')!=-1:
                CommentList.append(line[line.find('/*') + 2:line.find('*/')])
                continue
            if line.find('/*')!=-1:
                CommentList.append(line[line.find('/*') + 2:])
                Block_op=True
        return CommentList
#注释比率
    def calculateCommentRate(self, comment, codeLength):
        #self.authorinfo['commentNumber']+=len(comment)
        #self.authorinfo['codeLength']+=codeLength
        return math.log(len(comment) / codeLength)
# 计算函数的平均值和标准差
    def calculateFunctionInfo(self):
        if self.listener.functionNumber == 0:
            return None
        functionLength = []
        for function in self.listener.functionList:
            functionLength.append(function['functionEndLine'] - function['functionStartLine'] + 1)
            #self.funcLength.append(function['functionEndLine'] - function['functionStartLine'] + 1)
        return np.mean(functionLength),np.std(functionLength)
#变量定义的位置
    def calculateVariableLocationVariance(self):
        if self.listener.functionNumber == 0:
            return None
        variableRelativeLocationAfterNorm = []
        for function in self.listener.functionList:
            functionLength = function['functionEndLine'] - function['functionStartLine'] + 1
            for variable in function['localVariableList']:
                variableRelativeLocationAfterNorm.append(
                    (variable['Line'] - function['functionStartLine'] + 1) / functionLength)
        variableVariance = np.std(variableRelativeLocationAfterNorm)
        self.authorinfo['variableVariance']+=variableVariance
        return variableVariance
#变量命名词汇
    def analyseEnglishLevel(self, wordList):
        if len(wordList) == 0:
            return None
        with open('./WordLevel.json') as fp:
            englishDict = json.load(fp)
        englishScore = 0
        englishUsageTime = 0
        for word in wordList:
            if word.isalpha() and word in englishDict:
                englishScore += englishDict[word]
                englishUsageTime += 1
        self.authorinfo['englishScore']+=englishScore
        self.authorinfo['englishUsageTime']+=englishUsageTime
        return englishScore / englishUsageTime if englishUsageTime != 0 else 0
# 动态还是静态数组
    def calculateArray(self,file):
        static_rule='(.*?) \[(.*?)\]'
        dynamic_rules=['vector','new','malloc']
        dynamic_num=0
        static_num=0
        for line in file:
            static_num+=len(re.findall(static_rule,line))
            dynamic_num+=sum([len(re.findall(rule, line)) for rule in dynamic_rules])
        return static_num/dynamic_num

#预处理器
    def calculatePreprocessor(self,file,characterNum):
        pre_rules = [r'#define', r'#ifdef', r'#ifndef', r'#endif', r'__LINE__', r'__FILE__', r'__DATE__', r'__TIME__']
        preprocessNumber=0
        for line in file:
            preprocessNumber += sum([len(re.findall(rule, line)) for rule in pre_rules])
            #self.authorinfo['preprocessNumber']+=self.listener.preprocessNumber
        if preprocessNumber==0:
            return 0
        return (preprocessNumber,characterNum)
    def extractWordAndNamingConvention(self, identifier):
        '''
        Support Cammel and UnderScore Naming Convention

        Tip: When identifier is only a word, we assume its naming convention is UnderScore
        '''

        cammelPattern = re.compile('([a-z0-9]+|[A-Z][a-z0-9]+)((?:[A-Z0-9][a-z0-9]*)*)')
        result = cammelPattern.match(identifier)
        if result:
            wordList = []
            wordList.append(result.group(1))
            for word in re.findall('[A-Z0-9][a-z0-9]*', result.group(2)):
                wordList.append(word)
            return wordList, True

        underScorePattern = re.compile('[a-z0-9]+(_[a-z0-9]+)')
        if underScorePattern.match(identifier):
            wordList = identifier.split('_')
            return wordList, True

        return None, False

    def calculateEnglishLevelAndNormalNamingRate(self):
        identifierList = self.listener.identifierList
        if len(identifierList) == 0:
            return None, None
        normalIdentifierNumber = 0
        wordList = []
        for identifier in identifierList:
            wordFromIdentifier, isNormal = self.extractWordAndNamingConvention(identifier)
            if isNormal:
                wordList.extend(wordFromIdentifier)
                normalIdentifierNumber += 1
        englishLevel = self.analyseEnglishLevel(wordList)
        self.authorinfo['normalNumber']+=normalIdentifierNumber
        return englishLevel, normalIdentifierNumber / len(identifierList)
    # 匿名函数
    def calculateLambdaFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber == 0:
            return None
        self.authorinfo['lambdaNumber']+=self.listener.lambdaFunctionNumber
        return self.listener.lambdaFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    #异常,这里没有做改变，因为C++的异常处理都挺细致的
    def calculateIninlineFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber == 0:
            return None
        self.authorinfo['inlineNumber'] += self.listener.inlineFunctionNumber
        return self.listener.inlineFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateVirtualFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber == 0:
            return None
        self.authorinfo['virtualNumber'] += self.listener.virtualFunctionNumber
        return self.listener.virtualFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateTemplateFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber == 0:
            return None
        self.authorinfo['TemplateNumber'] += self.listener.templateFunctionNumber
        return self.listener.templateFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateStaticFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber == 0:
            return None
        self.authorinfo['staticNumber'] += self.listener.staticFunctionNumber
        return self.listener.staticFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculateExternFunctionNumber(self):
        if self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber == 0:
            return None
        self.authorinfo['ExternNumber'] += self.listener.externFunctionNumber
        return self.listener.externFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculatePointerFunctionNumber(self):
        if self.listener.pointerFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber== 0:
            return None
        self.authorinfo['PointerFunc'] += self.listener.pointerFunctionNumber
        return self.listener.pointerFunctionNumber / (self.listener.lambdaFunctionNumber + self.listener.functionNumber+self.listener.pointerFunctionNumber)
    def calculatePointerVariable(self):
        if self.listener.identifierNumber==0:
            return None
        self.authorinfo['PointerVar']+=self.listener.pointervarNumber
        return self.listener.pointervarNumber/self.listener.identifierNumber
    def calculateMemoryRecall(self,tokens):
        newNumber=0
        deleteNumber=0
        new_list=['new','malloc']
        delete_list=['delete','free']
        for tk in tokens:
            if tk in new_list:
                newNumber+=1
            elif tk in delete_list:
                deleteNumber+=1
        return (deleteNumber,newNumber)
    def IfSynchronization(self,tokens):
        if 'sync_with_stdio' in tokens:
            return 1
        else:
            return 0
    def calculateTokenRate(self, file,characterNum):
        token_list=[]
        for line in file:
            token_list.append( list(filter(None,re.split('[ \(\)\*;\{\}\[\]+=\-&/|%!?:,<>~`\t\r\n\"#$\']', line))))
        token_lists=[i for item in token_list for i in item]
        return token_lists,math.log(len(token_lists) / characterNum)
    def calculateKeywords(self,token,characterNum):
        keywords_list=['alignas','alignof','and','and_eq','asm','atomic_cancel','concept','const','consteval','constexpr',
                       'constinit','const_cast','continue','co_await','co_return','co_yield','atomic_commit','atomic_noexcept',
                        'auto','bitand', 'bitor', 'bool', 'break', 'case', 'catch', 'char', 'char8_t', 'char16_t', 'char32_t',
                       'class', 'compl','concept','const','consteval','constexpr','constinit','const_cast','continue','co_await',
                       'co_return','co_yield','decltype','default','delete','do','double','dynamic_cast','else','enum','explicit',
                       'export','extern','false','float','for','friend','goto','if','inline','int','long','mutable','namespace','new',
                       'noexcept','not','not_eq','nullptr','operator','or','or_eq','private','protected','public','reflexpr','register',
                       'reinterpret_cast','requires','return','short','signed','sizeof','static','static_assert','static_cast','struct',
                       'switch','synchronized','template','this','thread_local','throw','true','try','typedef','typeid','typename','union',
                       'unsigned','using','virtual','void','volatile','wchar_t','while','xor','xor_eq','final','override','transaction_safe',
                       'transaction_safe_dynamic','import','module','if','elif','else','endif','ifdef','ifndef','elifdef','elifndef','define',
                       'undef','include','line','error','warning','pragma','defined','__has_include','__has_cpp_attribute','export','import',
                       'module','_Pragma'#135
                       ]
        keyToken=0
        for tt in token:
            if tt in keywords_list:
                keyToken+=1
        if keyToken==0:
            return None
        return math.log(keyToken/characterNum)
    def calculateIDecrement(self,file):
        ope_tuple1=0
        ope_tuple2=0
        ope_tuple3=0
        for line in file:
            ope_tuple1+=len(re.findall(r'(\+\+)|(--)', str(line)))
            ope_tuple2+=len(re.findall(r'(\+=)|(-=)', str(line)))
            ope_tuple3+=len(re.findall(r'(\w+=\w+\+1)|(\w+=\w+-1)', str(line)))
        return (ope_tuple1,ope_tuple2,ope_tuple3)
    #def calculateMemoryAllocation(self,file):

    def calculateLayout(self,file,tokenLength):
        tab_rule=r'\t'
        white_space_rule=r' '
        white_line_rule=r'^\s*\n'
        tab_num=0
        indented_tab_num=0
        indented_space_num=0
        white_space_num=0
        white_line_num=0
        white_line_op=False
        new_line_cnt=0
        total_cnt=0
        for line in file:
            tab_num+=sum([len(re.findall(tab_rule, str(line)))])
            white_space_num+=sum([len(re.findall(white_space_rule, str(line)))])
            white_line_num_1=sum([len(re.findall(white_line_rule, str(line)))])
            white_line_num+=white_line_num_1
            if line.strip().find('{')!=-1:
                total_cnt += 1
                if white_line_op == True:
                    new_line_cnt += 1
            if white_line_num_1!=0:
                white_line_op=True
            else:
                white_line_op=False
            i=0
            while str(line)[i]==" " or str(line)[i]=="\t":
                i+=1
            if sum([len(re.findall(tab_rule, str(line[1:i-1])))]) >sum([len(re.findall(white_space_rule, str(line[1:i-1])))]):
                indented_tab_num +=1
            else:
                indented_space_num+=1
        tabsLeadLines=True
        if indented_tab_num<indented_space_num:
            tabsLeadLines=False
        if tokenLength==0:
            return None,None,None,None,None
        return tab_num/tokenLength, white_space_num/tokenLength,white_line_num/tokenLength,(tab_num+white_space_num)/(tokenLength-tab_num-white_space_num),new_line_cnt/total_cnt,tabsLeadLines
    # zkq
    def calculateAvgLineLength(self,file):
        sum_length_list = []
        for line in file:
            sum_length_list.append(len(line))
        return np.mean(sum_length_list),np.std(sum_length_list)
    def calculateKeyword(self,tokens,characterNum):
        sum_keyword = 0
        keyword = ['do', 'if', 'else','switch', 'for', 'while']
        for tk in tokens:
            if tk in keyword:
                sum_keyword+=1
        if sum_keyword==0:
            return None
        return math.log(sum_keyword/characterNum)
    def calculateTernary(self,file,characterNum):
        sum_ternary=0
        ternary = '[\s\S]*\?[\s\S]*\:[\s\S]*'
        for line in file:
            sum_ternary +=sum([len(re.findall(ternary, str(line)))])
        if sum_ternary==0:
            return None
        return math.log(sum_ternary/characterNum)
    def calculateNumLiterals(self,file,characterNum):
        sum_literals = 0
        target = '\"[\s\S]*\"|\'[\s\S]*\'|\-{0,1}[0-9]{1,}'
        for line in file:
            sum_literals += sum([len(re.findall(target, str(line)))])
        if sum_literals==0:
            return None
        return math.log(sum_literals/characterNum)
    def calculateAvgParams(self):
        if self.listener.functionNumber == 0:
            return 0
        sum_func = self.listener.functionNumber
        sum_params = []
        for func in self.listener.functionList:
            sum_params.append(func['ParamsNum'])
        return np.mean(sum_params),np.std(sum_params)
    def calculateParams(self):
        ParamNumList=[]
        for func in self.listener.functionList:
            ParamNumList.append(func['ParamsNum'])
        return np.mean(ParamNumList),np.std(ParamNumList)
    def calculateOpenness(self, newUsageRate):
        return newUsageRate

    def calculateConscientiousness(self, safetyUsageRate, normalNamingRate,
                                   longFunctionRate, commentRate,memoryRecallRate,pointerFunctionRate,pointercallRate,virtualFunctionRate,inlineFunctionRate,
                                   macroFunctionRate):
        conscientiousness = []

        if safetyUsageRate != None:
            conscientiousness.append(safetyUsageRate)

        if normalNamingRate != None:
            conscientiousness.append(normalNamingRate)

        if longFunctionRate != None:
            conscientiousness.append(max((1 - 1.3 * longFunctionRate), 0))

        if commentRate != None:
            if commentRate < 1 / 3:
                conscientiousness.append(5 / 3 * commentRate)
            elif commentRate < 2:
                conscientiousness.append(0.5 + 0.25 * commentRate)
            else:
                conscientiousness.append(0.5 - 0.1 * commentRate)
        if virtualFunctionRate != None:
            conscientiousness.append(0.5 + 0.5 * virtualFunctionRate)
        if inlineFunctionRate != None:
            conscientiousness.append(0.5 + 0.5 * inlineFunctionRate)
        if pointerFunctionRate != None:
            conscientiousness.append(0.5 - 0.5 * pointerFunctionRate)
        if pointercallRate != None:
            conscientiousness.append(0.5 - 0.5 * pointercallRate)

        if memoryRecallRate != None:
            conscientiousness.append(memoryRecallRate)
        if macroFunctionRate != None:
            conscientiousness.append(0.5 + 0.5 * macroFunctionRate)
        return np.mean(conscientiousness)

    def calculateExtroversion(self, commentRate):#外倾性：注释
        extroversion = []

        if commentRate != None:
            if commentRate < 1 / 3:
                extroversion.append(5 / 3 * commentRate)
            elif commentRate < 2:
                extroversion.append(0.5 + 0.25 * commentRate)
            else:
                extroversion.append(0.5 - 0.1 * commentRate)

        return np.mean(extroversion)

    def calculateAgreeableness(self, newUsageRate, longFunctionRate,lambdaFunctionrate):#宜人性
        agreeableness = []
        if newUsageRate != None:
            if newUsageRate < 0.5:
                agreeableness.append(0.5 - 0.5 * newUsageRate)
            else:
                agreeableness.append(0.5 + 0.5 * newUsageRate)

        if longFunctionRate != None:
            agreeableness.append(max((1 - 1.3 * longFunctionRate), 0))

        if lambdaFunctionrate != None:
            agreeableness.append(1 - 0.5 * lambdaFunctionrate)


        return np.mean(agreeableness)

    def calculateNeuroticism(self, normalNamingRate, localVariableVarience):
        neuroticism = []

        if normalNamingRate != None:
            neuroticism.append(normalNamingRate)

        if localVariableVarience != None:
            neuroticism.append(1 - localVariableVarience)#为什么是1-

        return np.mean(neuroticism)
    def calculateCharacterNum(self,file):
        characterNum=0
        for lines in file:
            characterNum+=len(lines)
        return characterNum
    def parse(self, filePath):
        #原先的生成树方式
        #tokenStream = CommonTokenStream(CPP14Lexer(FileStream(filePath)))
        #parser = CPP14Parser(tokenStream)
        #预测模式
        #parser._interp.predictionMode = PredictionMode.SLL
        walker=ParseTreeWalker()
        stt=time.time()
        #spam是自行编译的包,只能获得parseTree，不能提取到tokens
        tree=spam.build_tree(filePath)
        print("time",time.time()-stt)
        start_time=time.time()
        self.walker.walk(self.listener, tree)
        print("walk树时间：",time.time()-start_time)
        #format attention!!
        with open(filePath, 'rb') as fp:
            fileData=fp.read()
        fm=chardet.detect(fileData)
        fp.close()
        with open(filePath, 'r',encoding=fm['encoding']) as fp:
            fileData = fp.readlines()
        author_info={}
        # extract code features
        start_time=time.time()
        self.authorinfo['identifierNumber']=self.listener.identifierNumber
        #字符数
        characterNum=self.calculateCharacterNum(fileData)
        if characterNum==0:
            return None

        author_info['file']=filePath
        #token集合和token比率
        token,author_info['tokenRate']=self.calculateTokenRate(fileData,characterNum)
        #词频
        author_info['wordTF']=self.calculatewordTF(token)
        #注释集
        CommentList=self.extractComment(fileData)
        #注释比率
        author_info['commentRate'] = self.calculateCommentRate(CommentList,characterNum)
        #新旧调用，安全调用
        author_info['newUsageRate'], author_info['safetyUsageRate'] = self.calaulateUsage(fileData)
        #关键字比例
        author_info['keywordsRate']=self.calculateKeywords(token,characterNum)
        #循环关键字比例
        author_info['loopRate']=self.calculateKeyword(fileData,characterNum)
        #三目运算符比例
        author_info['ternaryRate']=self.calculateTernary(fileData,characterNum)
        #数字or字符比例
        author_info['LiteralRate']=self.calculateTernary(fileData,characterNum)
        #平均行长度,方差
        author_info['LineAverage'],author_info['LineStd']=self.calculateAvgLineLength(fileData)
        #平均函数长度，方差
        author_info['FunctionAvg'],author_info['FunctionStd']=self.calculateFunctionInfo()
        #平均参数个数，方差
        author_info['ParamAvg'],author_info['ParamStd']=self.calculateAvgParams()
        #局部变量的位置
        author_info['localVariableVarience'] = self.calculateVariableLocationVariance()
        #英语水平和命名水平
        author_info['englishLevel'], author_info['normalNamingRate'] = self.calculateEnglishLevelAndNormalNamingRate()
        #指针函数占所有函数比例
        author_info['pointerFunctionRate']=self.calculatePointerFunctionNumber()
        #虚函数占所有函数比例
        author_info['virtualFunctionRate']=self.calculateVirtualFunctionNumber()
        #inline函数占所有函数比例
        author_info['inlineFunctionRate']=self.calculateIninlineFunctionNumber()
        #外部函数占所有函数比例
        author_info['externFunctionRate']=self.calculateExternFunctionNumber()
        #匿名函数比例
        author_info['lambdaFunctionRate']=self.calculateLambdaFunctionNumber()
        #预处理器函数
        author_info['preprocessRate']=self.calculatePreprocessor(fileData,characterNum)
        #指针调用水平（需要改）
        author_info['pointercallRate']=self.calculatePointerVariable()
        #new和rate的比例
        author_info['memoryRecallRate']=self.calculateMemoryRecall(token)
        #布局计算
        author_info['tabsRate'],author_info['SpacesRate'],author_info['EmptyLineRate'],author_info['whiteSpaceRate'],author_info['newLineBeforeOpenBrace'],author_info['tabsLeadLines']=self.calculateLayout(fileData,characterNum)
        #是否需要sync with stdio
        author_info['Ifsync']=self.IfSynchronization(token)
        author_info['AvgParams'],author_info['stdParams']=self.calculateAvgParams()
        #动态还是静态数组
        author_info['arrays']=self.calculateArray(fileData)
        #递增方式
        author_info['IDecrement']=self.calculateIDecrement(fileData)
        # calculate psychological features
        #openness = self.calculateOpenness(newUsageRate)#开放性
        #conscientiousness = self.calculateConscientiousness(safetyUsageRate, normalNamingRate,
         #                          longFunctionRate, commentRate,memoryRecallRate,pointerFunctionRate,pointercallRate,virtualFunctionRate,inlineFunctionRate,
          #                         macroFunctionRate)#尽责性
        #extroversion = self.calculateExtroversion(commentRate)#外倾性
        #agreeableness = self.calculateAgreeableness(newUsageRate, longFunctionRate,lambdaFunctionRate)#宜人性
        #neuroticism = self.calculateNeuroticism(normalNamingRate, localVariableVarience)#情绪
        print("计算时间：",time.time()-start_time)
        #return self.authorinfo,openness #conscientiousness, extroversion, agreeableness, neuroticism
        return author_info
