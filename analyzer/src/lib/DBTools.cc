#include "DBTools.h"
#include <sstream>




void update_database(GlobalContext *Ctx){

    MYSQL *conn;
    //MYSQL_RES *sql_res;
    //MYSQL_ROW row;

    const char *server = "localhost";
    const char *user = "dinghaoliu";
    const char *pwd = "";
    const char *database = "icall_data";
 
    string table_name_icall = "icall_target_table";
    string table_name_caller = "caller_table";
    //string table_name = "test_table";
    string drop_table_icall = "drop table if exists " + table_name_icall;
    string drop_table_caller = "drop table if exists " + table_name_caller;

    string create_table_icall = "create table " + table_name_icall;
    string create_table_caller = "create table " + table_name_caller;

    create_table_icall += "( id int auto_increment, ";
    create_table_icall += "line_number int, ";
    create_table_icall += "caller_func varchar(60), ";
    create_table_icall += "target_num int, ";
    create_table_icall += "MLTA_result varchar(20), ";
    create_table_icall += "Alias_result int, ";
    create_table_icall += "target_set_hash varchar(30), ";
    create_table_icall += "primary key(id));";

    create_table_caller += "( id int auto_increment, ";
    create_table_caller += "func_set_hash varchar(30), ";
    create_table_caller += "func_name varchar(70), ";
    create_table_caller += "primary key(id));";

    MYSQL mysql;
    conn = mysql_init(&mysql);

    if(!mysql_real_connect(conn, server, user, pwd, database, 0, NULL, 0)){
        OP<<"WARNING: MYSQL connect failed!\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return;
    }

    OP<<"MYSQL connect succeed!\n";

    //First clean the old table data
    if(mysql_query(conn, drop_table_icall.c_str())) {
        OP<<"Drop table 1 failed\n";
        return;
    }

    //Create a new table to record our data
    if(mysql_query(conn, create_table_icall.c_str())) {
        OP<<"Create table 1 failed\n";
        return;
    }

    //Insert new icall results
    vector<string> cmds;
    cmds.clear();
    build_insert_batch_for_icall_table(Ctx, 500, cmds);
    for(unsigned i = 0; i < cmds.size(); i++){
        string insert_cmd = cmds[i];
        if(mysql_query(conn, insert_cmd.c_str())) {
            OP<<"Insert table 1 failed\n";
            OP<<"cmd: "<<insert_cmd<<"\n";
        }
    }
    cmds.clear();

    OP<<"icall_target_table build succeed!\n";

    //First clean the old table data
    if(mysql_query(conn, drop_table_caller.c_str())) {
        OP<<"Drop table 2 failed\n";
        return;
    }

    //Create a new table to record our data
    if(mysql_query(conn, create_table_caller.c_str())) {
        OP<<"Create table 2 failed\n";
        return;
    }

    //Insert new caller results
    build_insert_batch_for_caller_table(Ctx, 500, cmds);
    for(unsigned i = 0; i < cmds.size(); i++){
        string insert_cmd = cmds[i];
        if(mysql_query(conn, insert_cmd.c_str())) {
            OP<<"Insert table 2 failed\n";
            OP<<"cmd: "<<insert_cmd<<"\n";
        }
    }


    OP<<"caller_table build succeed!\n";

    //sql_res = mysql_use_result(conn);
    //OP<<*sql_res<<"\n";
    //while ((row = mysql_fetch_row(sql_res)) != NULL)
    //    OP<<row[0]<<"\n";

    OP<<"MYSQL update succeed!\n";
    //Close connection
    mysql_close(&mysql);
    
}

//Used to speed up database insert
void build_insert_batch_for_icall_table(GlobalContext *Ctx, int batch_size, vector<string> &cmds){

    string insert_statement;

    stringstream insertss;
    insertss << "insert into icall_target_table ";
    insertss << "(line_number, caller_func, target_num, MLTA_result, Alias_result, target_set_hash) values ";

    int batchnum = 0;
    unsigned icallnum = Ctx->ICallees.size();
    unsigned icallid = 1;
    for(auto i = Ctx->ICallees.begin(); i!= Ctx->ICallees.end(); i++){

        batchnum++;
        
        CallInst* cai = i->first;
        FuncSet fset = i->second;
        unsigned lineNo = getInstLineNo(cai);
        unsigned long long num = fset.size();
        Function* caller = cai->getFunction();

        insertss << "(";
        insertss << lineNo << ",";
        insertss << "\"" <<  caller->getName().str()  << "\"" << "," << num << ",";
        switch(Ctx->Global_MLTA_Reualt_Map[cai]){
            case TypeEscape:
                insertss << "\"" << "TypeEscape"  << "\"";
                break;
            case OneLayer:
                insertss << "\"" << "OneLayer" << "\"";
                break;
            case TwoLayer:
                insertss << "\"" << "TwoLayer" << "\"";
                break;
            case ThreeLayer:
                insertss << "\"" << "ThreeLayer" << "\"";
                break;
            case NoTwoLayerInfo:
                insertss << "\"" << "NoTwoLayerInfo" << "\"";
                break;
            case MissingBaseType:
                insertss << "\"" << "MissingBaseType" << "\"";
                break;
            default:
                insertss << "\"" << "unknown" << "\"";
                break;
        }

        insertss << "," << Ctx->Global_Alias_Results_Map[cai];

        stringstream ss;
        ss<<funcSetHash(fset);

        insertss << "," << "\"" << ss.str() << "\"";

        insertss << ")";

        //Stop batch collection and build a new batch
        if(batchnum >= batch_size || icallid == icallnum){
            batchnum = 0;

            insertss << ";";
            cmds.push_back(insertss.str());
            //OP<<"cmds: "<<insertss.str()<<"\n";
            insertss.str("");

            if(icallid != icallnum){
                insertss << "insert into icall_target_table ";
                insertss << "(line_number, caller_func, target_num, MLTA_result, Alias_result, target_set_hash) values ";
            }
        }
        else{
            insertss << ",";
        }

        icallid++;
        
    }//end for loop

}

//Used to speed up database insert
void build_insert_batch_for_caller_table(GlobalContext *Ctx, int batch_size, vector<string> &cmds){

    string insert_statement;

    stringstream insertss;
    insertss << "insert into caller_table ";
    insertss << "(func_set_hash, func_name) values ";

    int batchnum = 0;
    unsigned long long icallnum = 0;
    unsigned long long icallid = 1;

    map<size_t, FuncSet> funcHashMap;
    funcHashMap.clear();
    set<size_t> funcHashSet;
    funcHashSet.clear();

    for(auto i = Ctx->ICallees.begin(); i!= Ctx->ICallees.end(); i++){
        FuncSet fset = i->second;
        if(fset.empty())
            continue;

        size_t funcsethash = funcSetHash(fset);
        if(funcHashSet.count(funcsethash))
            continue;

        funcHashSet.insert(funcsethash);

        //size_t funcsethash = funcSetHash(fset);
        //funcHashMap[funcsethash] = fset;
        icallnum += fset.size();
    }

    OP<<"icallnum: "<<icallnum<<"\n";
    //return;

    funcHashSet.clear();

    for(auto i = Ctx->ICallees.begin(); i!= Ctx->ICallees.end(); i++){

        CallInst* cai = i->first;
        FuncSet fset = i->second;
        if(fset.empty())
            continue;
        
        size_t funcsethash = funcSetHash(fset);
        if(funcHashSet.count(funcsethash))
            continue;
        funcHashSet.insert(funcsethash);
        
        for(auto j = fset.begin(); j != fset.end(); j++){
            batchnum++;

            Function* f = *j;

            insertss << "(";
            stringstream ss;
            ss << funcsethash;
            insertss << "\"" << ss.str() << "\"" << ",";

            insertss << "\"" <<  f->getName().str()  << "\"" ;
            insertss << ")";

            //Stop batch collection and build a new batch
            if(batchnum >= batch_size || icallid == icallnum){
                batchnum = 0;

                insertss << ";";
                cmds.push_back(insertss.str());
                //OP<<"cmds: "<<insertss.str()<<"\n";
                insertss.str("");

                if(icallid != icallnum){
                    insertss << "insert into caller_table ";
                    insertss << "(func_set_hash, func_name) values ";
                }
            }
            else{
                insertss << ",";
            }

            icallid++;
            
        }

        
        
    }//end for loop

}

size_t funcSetHash(FuncSet fset){
    
    size_t Funcsethash = 0;
    
    for(auto i = fset.begin(); i != fset.end(); i++){
        Function* f = *i;
        hash<string> str_hash;
        Funcsethash += str_hash(f->getName());
    }
    return Funcsethash;
}
