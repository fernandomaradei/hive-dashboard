#!/usr/bin/env python3
"""PCAP -> SQL Cloudflare D1. Sem correto.csv, sem acesso remoto, sem bibliotecas externas.
Uso: python HIVE_Exportador_D1_v3_4.py HIVESTxASGARD2.pcapng --guild Hivest
"""
import argparse, csv, datetime as dt, hashlib, importlib.util, json, sqlite3
from pathlib import Path

HERE=Path(__file__).resolve().parent

def load(path):
    spec=importlib.util.spec_from_file_location('hive_parser_v33',str(path))
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def one(fields,num,wire=None):
    return next((v for f,w,v in fields if f==num and (wire is None or w==wire)),None)

def report_metadata(pcap, parser, rows):
    import struct,zlib
    wanted=int(rows[0]['_match_id'])
    for _,stream in parser.tcp_streams(str(pcap)):
        pos=0
        while pos+4<=len(stream):
            size=struct.unpack_from('<I',stream,pos)[0]
            if not 8<=size<=8000000 or pos+4+size>len(stream):pos+=1;continue
            msg=stream[pos+4:pos+4+size];pos+=4+size
            if len(msg)<15 or msg[4]!=5:continue
            for offset in (12,8,16):
                try:
                    root=parser.parse_pb(zlib.decompress(msg[offset:]));match=parser.parse_pb(one(root,2,2))
                    if one(match,1,0)!=wanted:continue
                    data=parser.parse_pb(one(match,10,2))
                    guilds={}
                    for f,w,v in match:
                        if f in (4,5) and w==2:
                            info=parser.parse_pb(v);gid=one(info,5,0);name=one(info,3,2)
                            if gid is not None and name is not None:guilds[str(gid)]={'id':str(gid),'name':name.decode('utf8')}
                    for f,w,v in data:
                        if f!=3 or w!=2:continue
                        team=parser.parse_pb(v);gid=str(one(team,1,0));group=parser.parse_pb(one(team,2,2))
                        scores={}
                        for a,b,raw in group:
                            if a!=3 or b!=2:continue
                            item=parser.parse_pb(raw);scores[one(item,1,0)]=one(item,2,0)
                        if gid in guilds:guilds[gid].update(score=scores.get(8),kills=scores.get(2))
                    tz=dt.timezone(dt.timedelta(hours=-3))
                    start=dt.datetime.fromtimestamp(one(match,9,0),tz)
                    end_ts=one(match,3,0)
                    end=dt.datetime.fromtimestamp(end_ts,tz) if end_ts and end_ts>1000000000 else None
                    winner=str(one(data,2,0)) if one(data,2,0) is not None else None
                    if len(guilds)!=2:raise ValueError('Duas guildas nao encontradas no relatorio')
                    return {'match_id':str(wanted),'started_at':start.isoformat(),'ended_at':end.isoformat() if end else None,'battle_date':start.date().isoformat(),'guilds':guilds,'winner_id':winner}
                except (ValueError,TypeError,UnicodeError,StopIteration,zlib.error):continue
    raise ValueError('Metadados da partida nao localizados no PCAP')

def sql_literal(value):
    if value is None:return 'NULL'
    if isinstance(value,bool):return '1' if value else '0'
    if isinstance(value,(int,float)):return str(value)
    return "'"+str(value).replace("'","''")+"'"

def insert(table,values):
    return f"INSERT INTO {table} ("+','.join(values)+") VALUES ("+','.join(sql_literal(x) for x in values.values())+");"

def make(pcap,guild,parser):
    reports=parser.find_reports(str(pcap))
    if len(reports)!=1:raise ValueError(f'Esperado 1 relatorio no PCAP; encontrados {len(reports)}')
    rows=reports[0]
    if not rows or any(r.get('_layout')!='vigrid_salt' for r in rows):raise ValueError('Somente o layout de guerra validado e aceito')
    meta=report_metadata(pcap,parser,rows)
    our=next((g for g in meta['guilds'].values() if g['name'].casefold()==guild.casefold()),None)
    if not our:raise ValueError('Guilda informada nao encontrada no PCAP: '+guild)
    opp=next(g for g in meta['guilds'].values() if g['id']!=our['id'])
    winner=meta['guilds'].get(meta['winner_id'])
    if not winner:result='INDEFINIDO'
    elif winner['id']==our['id']:result='VITORIA'
    else:result='DERROTA'
    source_hash=hashlib.sha256(pcap.read_bytes()).hexdigest()
    war={
        'match_id':meta['match_id'],'started_at':meta['started_at'],'ended_at':meta['ended_at'],
        'battle_date':meta['battle_date'],'our_guild_id':our['id'],'our_guild_name':our['name'],
        'opponent_guild_id':opp['id'],'opponent_guild_name':opp['name'],
        'winner_guild_id':winner['id'] if winner else None,'winner_guild_name':winner['name'] if winner else None,
        'result':result,'our_score':our.get('score'),'opponent_score':opp.get('score'),
        'our_kills':our.get('kills'),'opponent_kills':opp.get('kills'),
        'raw_match_json':json.dumps(meta,ensure_ascii=False,separators=(',',':'))}
    commands=['-- Gerado exclusivamente do PCAP. Nao utiliza correto.csv.',
              '-- Verifica duplicidade por ID da partida; nao sobrescreve guerra anterior.',
              'BEGIN TRANSACTION;',
              insert('hive_wars',war).replace('INSERT INTO hive_wars','INSERT OR IGNORE INTO hive_wars',1)]
    players=[]
    for r in rows:
        def c(n):return int(r.get('C:'+str(n),0) or 0)
        # C:20+C:23+C:51+C:65+C:66 = monstros; C:62 = ressuscitacoes.
        # Merito: K+C:18+2*C:20+2*C:65+15*C:19+15*C:51.
        merit=c(2)+c(18)+2*c(20)+2*c(65)+15*c(19)+15*c(51)
        raw={k:v for k,v in r.items() if k.startswith('C:')}
        item={'war_id':None,'character_id':str(r['ID_Personagem']),'character_name':r['Personagem'],
              'guild_id':str(r['Guilda_ID']),'guild_name':r['Guilda'],
              'job_id':int(r.get('2:4') or 0),'job_name':parser.job_from_code(r.get('2:4')),
              'battlefield':{1:'PRINCIPAL',2:'SECUNDARIO'}.get(r['Tipo_Estatisticas']),
              'stats_type':r['Tipo_Estatisticas'],'power':r.get('Power'),
              'kills':c(2),'deaths':c(3),'assists':c(4),
              'damage_dealt':c(64),'damage_received':c(71),'healing':c(48),
              'duration_seconds':r.get('C:63'),'pp_vigrid':c(1),
              'gp':c(8) if 'C:8' in r else None,
              'merit':merit if any('C:'+str(n) in r for n in (18,19,20,51,65)) else None,
              'resurrections':c(62),'monsters':c(20)+c(23)+c(51)+c(65)+c(66),
              'raw_stats_json':json.dumps(raw,ensure_ascii=False,separators=(',',':'))}
        players.append(item)
        vals={k:v for k,v in item.items() if k!='war_id'}
        cols='war_id,'+','.join(vals)
        params='(SELECT id FROM hive_wars WHERE match_id='+sql_literal(meta['match_id'])+'),'+','.join(sql_literal(v) for v in vals.values())
        commands.append('INSERT OR IGNORE INTO hive_war_players ('+cols+') VALUES ('+params+');')
    imp={'war_id':None,'source_filename':pcap.name,'source_sha256':source_hash,'parser_version':'3.4',
         'status':'CONCLUIDO','total_players':len(players),'notes':'Somente PCAP; titulos excluidos'}
    iv={k:v for k,v in imp.items() if k!='war_id'}
    commands.append('INSERT OR IGNORE INTO hive_war_imports (war_id,'+','.join(iv)+') VALUES ((SELECT id FROM hive_wars WHERE match_id='+sql_literal(meta['match_id'])+'),'+','.join(sql_literal(v) for v in iv.values())+');')
    commands+=['COMMIT;','SELECT id,match_id,battle_date,opponent_guild_name,result FROM hive_wars WHERE match_id='+sql_literal(meta['match_id'])+';']
    return '\n'.join(commands)+'\n',war,players

def main():
    a=argparse.ArgumentParser();a.add_argument('pcap',type=Path);a.add_argument('--guild',default='Hivest');a.add_argument('--parser',type=Path,default=HERE/'extrator_hive_d1_v3_3_minutos.py');a.add_argument('--output',type=Path);args=a.parse_args()
    parser=load(args.parser);sql,war,players=make(args.pcap,args.guild,parser)
    out=args.output or args.pcap.with_name('HIVE_Importar_'+war['battle_date']+'.sql');out.write_text(sql,encoding='utf8')
    print('SQL:',out,'\nPartida:',war['match_id'],'\nAdversario:',war['opponent_guild_name'],'\nJogadores:',len(players))
if __name__=='__main__':main()
