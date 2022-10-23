from os import access
from .CPP14Parser import CPP14Parser
from .CPP14ParserListener import CPP14ParserListener
from .CPP14ParserVisitor import CPP14ParserVisitor
from antlr4 import *
import re
class CPP14Extract(CPP14ParserListener):
    def __init__(self):
        super().__init__()
        self.functionNumber = 0
        self.functionList = []
        self.lambdaFunctionNumber = 0
        self.virtualFunctionNumber=0
        self.inlineFunctionNumber=0
        self.templateFunctionNumber=0
        self.staticFunctionNumber=0
        self.externFunctionNumber=0
        self.pointerFunctonNumber=0
        #variable-based
        self.identifierList=[]
        self.identifierNumber=0
        self.pointervarNumber=0
        self.globalNumber=0
        # class-based
        self.classNameList = []
        self.classNumber = 0
        self.classVariableNameList = []
        self.classVariableNumber = 0
        # quote 引用
        self.importNumber = 0
        self.importNameList= []
        # code style
        self.packageNumber = 0
        self.packageNameList = []
        self.newNumber=0
        self.deleteNumber=0
        self.macroNumber=0
        #error-based
        self.throwNumber = 0
        self.throwNameList = []
        self.tryNumber=0
        self.tryList=[]
        self.catchNumber=0
        self.catchList=[]
        #layout
        self.space=0
        #Comment
        self.CommentList=[]
        #namespace
        self.namespaceNum=0
        self.exceptionNumber=0
        #access
        self.accessnum=0
        self.accessdict={"public":0,"protected":0,"private":0}
        #constructor
        self.Constructor=0
    #需要function_number classname_list classvaribale_list
    def enterFunctionDefinition(self, ctx:CPP14Parser.FunctionDefinitionContext):
        # capture function information
        functionBody = ctx.getText()
        functionStartLine = ctx.start.line
        functionEndLine = ctx.stop.line
        Pos=functionBody[functionBody.find('(')+1:functionBody.find(')')]
        posNum=0
        if re.match(r'\s*\S',Pos)!=None:
            posNum=len(re.findall(r',',Pos))+1
        self.functionList.append(
            {
                'functionBody': functionBody,
                'functionStartLine': functionStartLine,
                'functionEndLine': functionEndLine,
                'localVariableList': [],
                'functionCallList': [],
                'ParamsNum':posNum,
            }
        )
        self.functionNumber += 1
        return super().enterFunctionDefinition(ctx)
    def enterLambdaExpression(self, ctx:CPP14Parser.LambdaExpressionContext):
        self.lambdaFunctionNumber+=1
        return super().enterLambdaExpression(ctx)
    #inline没有
    def enterTemplateDeclaration(self, ctx:CPP14Parser.TemplateDeclarationContext):
        self.templateFunctionNumber+=1
        return super().enterTemplateDeclaration(ctx)
    def enterIdExpression(self, ctx:CPP14Parser.IdExpressionContext):
        identifiername=ctx.getText()
        self.identifierList.append(identifiername)
        self.identifierNumber+=1
        return super().enterIdExpression(ctx)
    def enterFunctionSpecifier(self, ctx:CPP14Parser.FunctionSpecifierContext):
        functionSpecifierName = ctx.getText()
        functionCallLine = ctx.start.line
        functionCallColumn = ctx.start.column
        rules_static = r'static'  # 静态函数
        if functionSpecifierName != "":
            if re.findall(rules_static, functionSpecifierName) != []:
                self.staticFunctionNumber += 1
            rules_virtual = r'virtual'
            if re.findall(rules_virtual, functionSpecifierName) != []:
                self.virtualFunctionNumber += 1
            rules_inline = r'inline'
            if re.findall(rules_inline, functionSpecifierName) != []:
                self.inlineFunctionNumber += 1
        return super().enterFunctionSpecifier(ctx)

    def enterDeclarator(self, ctx:CPP14Parser.DeclaratorContext):
        declaratorName=ctx.getText()
        declaratorline=ctx.stop.line
        if declaratorName.find('*')!=-1 and declaratorName.find("(")==-1:
            self.pointervarNumber+=1
        if declaratorName[0].find('*')!=-1 and declaratorName.find("(")!=-1:
            self.pointerFunctionNumber+=1
        if declaratorName[0]=='*' or declaratorName[0]=='&':
            declaratorName=declaratorName[1:]
        if declaratorName.find("(")!=-1:
            declaratorName=declaratorName[:declaratorName.find("(")]
        if declaratorName.find("[")!=-1:
            declaratorName=declaratorName[:declaratorName.find("[")]
        #rules_pointer = r'(.*?) \(\*(.*?)\)'  # 函数指针
        #if re.findall(rules_pointer, declaratorName) != []:
         #   self.pointerFunctionNumber += 1
        if len(self.functionList) != 0:
            if self.functionList[-1]['functionEndLine'] > declaratorline and self.functionList[-1]['functionStartLine']<declaratorline:
                self.functionList[-1]['localVariableList'].append(
                    {
                        'variableName':declaratorName,
                        'Line': declaratorline
                    }
                )
            else:
                self.globalNumber+=1
        self.identifierList.append(declaratorName)
        self.identifierNumber+=1
        return super().enterDeclarator(ctx)
    def enterExceptionDeclaration(self, ctx:CPP14Parser.ExceptionDeclarationContext):
        exceptionName=ctx.getText()
        self.exceptionNameList.append(exceptionName)
        self.exceptionNumber += 1
        return super().enterExceptionDeclaration(ctx)
    def enterThrowExpression(self, ctx:CPP14Parser.ThrowExpressionContext):
        exceptionName=ctx.getText()
        self.throwNameList.append(exceptionName)
        self.throwNumber += 1
        return super().enterExceptionDeclaration(ctx)
    def enterTryBlock(self, ctx:CPP14Parser.TryBlockContext):
        self.tryList.append(ctx.getText())
        self.tryNumber+=1
        return super().enterTryBlock(ctx)
    def enterNewExpression(self, ctx:CPP14Parser.NewExpressionContext):
        self.newNumber+=1
        return super().enterNewExpression(ctx)
    def enterDeleteExpression(self, ctx:CPP14Parser.DeleteExpressionContext):
        self.deleteNumber+=1
        return super().enterDeleteExpression(ctx)
    def enterNamespaceDefinition(self, ctx: CPP14Parser.NamespaceDefinitionContext):
        self.namespaceNum+=1
        return super().enterNamespaceDefinition(ctx)
    def enterAccessSpecifier(self, ctx: CPP14Parser.AccessSpecifierContext):
        access_text=ctx.getText()
        if access_text.find("public")!=-1:
            self.accessdict["public"]+=1
        elif access_text.find("protected")!=-1:
            self.accessdict["protected"]+=1
        elif access_text.find("private")!=-1:
            self.accessdict["private"]+=1
        return super().enterAccessSpecifier(ctx)
    def enterConstructorInitializer(self, ctx: CPP14Parser.ConstructorInitializerContext):
        self.Constructor+=1
        return super().enterConstructorInitializer(ctx)