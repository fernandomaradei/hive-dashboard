"""Extrator local de relatórios KDA do Ragnarok Origin Classic (PCAPNG). Sem dependências externas."""
import csv
import hashlib
import json
import urllib.request
import urllib.error
import ipaddress
import os
import struct
import sys
import zlib
from collections import defaultdict
from pathlib import Path

# DE-PARA validado com jogadores informados pela guilda.
JOB_CODES = {
    2102: 'Lord Knight',
    2202: 'Paladin',
    3102: 'High Priest',
    4102: 'High Wizard',
    4202: 'Professor',
    6202: 'Biochemist',
    7102: 'Sniper',
    7202: 'MUSIC',
    7212: 'MUSIC',
    8102: 'Doram',
    9102: 'Gunslinger',
}

def job_from_code(code):
    return JOB_CODES.get(code, 'Não identificado')


CENTRAL_URL = 'https://hive-rooc.com.br/api/wars/import'
CAMPOS_CONHECIDOS = {
    '1:0','1:40','1:1','1:21','1:13','1:12','1:11',
    '2:1','2:2','2:4','2:19','2:18','2:20'
}

def preparar_envio(rows, token, data='', placar1='', placar2=''):
    """Monta o payload aceito pelo Apps Script, sem transmitir o PCAP."""
    if any(r.get('_layout') == 'vigrid_salt' for r in rows):
        raise ValueError('Vigrid/Salt identificado: ainda falta validar K/D/A, dano e cura. Esta modalidade nao exige ocupacoes. CSV diagnostico gerado; envio bloqueado para proteger os dados.')
    guilds = sorted({r['Guilda'] for r in rows if r['Guilda'] != 'Não identificada'})
    if len(guilds) != 2:
        raise ValueError('Esperadas exatamente duas guildas identificadas. Encontradas: '+', '.join(guilds))
    # ID determinístico calculado a partir dos dados do confronto, não do nome do arquivo.
    assinatura = sorted([
        [r['Personagem'], r['Guilda'], r.get('1:21',0),
         r.get('1:40',0), r.get('1:1',0), r.get('1:13',0),
         r.get('1:12',0), r.get('1:11',0)]
        for r in rows
    ])
    digest = hashlib.sha256(json.dumps(assinatura, ensure_ascii=False, separators=(',',':')).encode('utf-8')).hexdigest()[:24]
    guerra_id = 'ROO-' + digest
    def valor(x):
        if x is None or x == '': return None
        return int(x)
    def numero(r, k):
        return int(r.get(k, 0) or 0)
    jogadores = []
    campos = []
    for r in rows:
        jogadores.append({
            'personagem':r['Personagem'], 'guilda':r['Guilda'],
            'guilda_id':int(r['Guilda_ID']), 'job':job_from_code(r.get('2:4')),
            'job_codigo':numero(r,'2:4'), 'kills':numero(r,'1:0'),
            'assistencias':numero(r,'1:40'), 'mortes':numero(r,'1:1'),
            'ocupacoes':numero(r,'2:2'), 'pontuacao':numero(r,'1:21'),
            'dano_causado':numero(r,'1:13'), 'dano_recebido':numero(r,'1:12'),
            'cura':numero(r,'1:11'), 'pontos_assistencias':numero(r,'2:19'),
            'pontos_mortes':numero(r,'2:18'), 'pontos_ocupacoes':numero(r,'2:20')
        })
        for k,v in r.items():
            if ':' in k and k not in CAMPOS_CONHECIDOS and isinstance(v,int):
                campos.append({'personagem':r['Personagem'],'guilda':r['Guilda'],
                               'codigo':k,'descricao':'Nao_Identificado','valor':v})
    return {
        'guerra':{'id':guerra_id,'mode':'legacy','source_hash':hashlib.sha256(json.dumps(assinatura,ensure_ascii=False,separators=(',',':')).encode('utf-8')).hexdigest(),'data':data,'guilda1':guilds[0],
                  'guilda2':guilds[1],'placar1':valor(placar1),'placar2':valor(placar2)},
        'jogadores':jogadores,'campos':campos
    }

def enviar_central(payload, token, url=CENTRAL_URL):
    data=json.dumps(payload,ensure_ascii=False).encode('utf-8')
    req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json; charset=utf-8','Authorization':'Bearer '+token},
                               method='POST')
    try:
        with urllib.request.urlopen(req,timeout=60) as resp:
            result=json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as exc:
        corpo = exc.read().decode('utf-8', errors='replace')
        raise RuntimeError(
            f'HTTP {exc.code} - {corpo[:1500]}'
        ) from exc
    except (urllib.error.URLError, ValueError) as exc:
        raise RuntimeError('Falha de conexão/resposta da Central: '+str(exc)) from exc
    if not result.get('ok'):
        raise RuntimeError('D1 recusou o envio: '+str(result.get('error',result.get('erro','erro desconhecido'))))
    return result

MAX_BLOCK = 32 * 1024 * 1024
MAX_STREAM = 64 * 1024 * 1024

def packets_pcapng(path):
    b = Path(path).read_bytes()
    pos = 0
    interfaces = []
    while pos + 12 <= len(b):
        typ, size = struct.unpack_from('<II', b, pos)
        if size < 12 or size > MAX_BLOCK or pos + size > len(b):
            raise ValueError('Bloco PCAPNG inválido ou formato não suportado.')
        body = b[pos + 8:pos + size - 4]
        if typ == 1 and len(body) >= 2:
            interfaces.append(struct.unpack_from('<H', body)[0])
        elif typ == 6 and len(body) >= 20:
            iface, hi, lo, cap, orig = struct.unpack_from('<IIIII', body)
            if iface < len(interfaces) and interfaces[iface] == 1:
                frame = body[20:20 + cap]
                if len(frame) >= 34 and frame[12:14] == b'\x08\x00':
                    ip = frame[14:]
                    ihl = (ip[0] & 15) * 4
                    if len(ip) >= ihl + 20 and ip[9] == 6:
                        total = min(len(ip), struct.unpack_from('!H', ip, 2)[0])
                        sport, dport, seq, ack, offset = struct.unpack_from('!HHIIH', ip, ihl)
                        thl = (offset >> 12) * 4
                        payload = ip[ihl + thl:total]
                        if payload:
                            src = str(ipaddress.IPv4Address(ip[12:16]))
                            dst = str(ipaddress.IPv4Address(ip[16:20]))
                            yield (src, sport, dst, dport), seq, payload
        pos += size

def tcp_streams(path):
    groups = defaultdict(list)
    for flow, seq, payload in packets_pcapng(path):
        # Nenhuma porta fixa: o jogo pode mudar a porta entre servidores/sessoes.
        # O protocolo e validado depois (envelope, zlib e registros de jogadores).
        groups[flow].append((seq, payload))
    for flow, packets in groups.items():
        packets.sort()
        base = packets[0][0]
        end = max(s + len(d) for s, d in packets)
        if end - base > MAX_STREAM:
            continue
        buf = bytearray(end - base)
        filled = bytearray(end - base)
        for seq, data in packets:
            start = seq - base
            buf[start:start + len(data)] = data
            filled[start:start + len(data)] = b'\x01' * len(data)
        # Ignore streams with missing bytes: otherwise a malformed report could be exported.
        if 0 not in filled:
            yield flow, bytes(buf)

def read_varint(b, p):
    value = 0
    for i in range(10):
        if p >= len(b):
            raise ValueError('Varint truncado')
        byte = b[p]
        p += 1
        value |= (byte & 127) << (7 * i)
        if byte < 128:
            return value, p
    raise ValueError('Varint inválido')

def parse_pb(b):
    p = 0
    result = []
    while p < len(b):
        tag, p = read_varint(b, p)
        field, wire = tag >> 3, tag & 7
        if not field:
            raise ValueError('Campo inválido')
        if wire == 0:
            value, p = read_varint(b, p)
        elif wire == 2:
            n, p = read_varint(b, p)
            if n > len(b) - p:
                raise ValueError('Tamanho inválido')
            value = b[p:p + n]
            p += n
        elif wire == 1:
            if p + 8 > len(b): raise ValueError('Truncado')
            value = b[p:p + 8]
            p += 8
        elif wire == 5:
            if p + 4 > len(b): raise ValueError('Truncado')
            value = b[p:p + 4]
            p += 4
        else:
            raise ValueError('Wire type não suportado')
        result.append((field, wire, value))
    return result

def _parse_salt_report(raw):
    """Une dados de identidade e estatisticas por ID do jogador (Vigrid)."""
    try:
        root=parse_pb(raw)
        match=parse_pb(next(v for f,w,v in root if f==2 and w==2))
        match_id=next(v for f,w,v in match if f==1 and w==0)
        guilds={}
        for f,w,v in match:
            if f in (4,5) and w==2:
                a=parse_pb(v)
                gid=next((x for k,t,x in a if k==5 and t==0),None)
                name=next((x.decode('utf8') for k,t,x in a if k==3 and t==2),None)
                if gid is not None and name:guilds[gid]=name
        data=next(v for f,w,v in match if f==10 and w==2)
        teams=[v for f,w,v in parse_pb(data) if f==3 and w==2]
    except (ValueError,StopIteration,UnicodeDecodeError):return []
    rows=[]
    for team in teams:
        try:
            tf=parse_pb(team)
            gid=next(v for f,w,v in tf if f==1 and w==0)
            group=parse_pb(next(v for f,w,v in tf if f==2 and w==2))
            stats={}
            for f,w,wrapper in group:
                if f!=2 or w!=2:continue
                wp=parse_pb(wrapper)
                typ=next((v for k,t,v in wp if k==1 and t==0),None)
                inner=next((v for k,t,v in wp if k==2 and t==2),None)
                if inner is None:continue
                for k,t,entry in parse_pb(inner):
                    if k not in (3,4) or t!=2:continue
                    ep=parse_pb(entry)
                    pid=next((v for a,b,v in ep if a==1 and b==0),None)
                    payload=next((v for a,b,v in ep if a==2 and b==2),None)
                    if pid is None or payload is None:continue
                    codes={}
                    for a,b,pair in parse_pb(payload):
                        if a!=1 or b!=2:continue
                        p=parse_pb(pair)
                        code=next((v for x,y,v in p if x==1 and y==0),None)
                        val=next((v for x,y,v in p if x==2 and y==0),None)
                        if code is not None and val is not None:codes[code]=val
                    if pid not in stats:
                        stats[pid]=(typ,{})
                    previous_typ, accumulated = stats[pid]
                    for code, val in codes.items():
                        accumulated[code] = accumulated.get(code, 0) + val
            # Tempo historico por jogador: group.field6 -> id, metricas -> codigo 63 (segundos).
            tempos = {}
            for f, w, entry in group:
                if f != 6 or w != 2:
                    continue
                gp = parse_pb(entry)
                player_id = next((v for k, t, v in gp if k == 1 and t == 0), None)
                if player_id is None:
                    continue
                for k, t, metrics in gp:
                    if k != 2 or t != 2:
                        continue
                    for a, b, metric in parse_pb(metrics):
                        if a != 1 or b != 2:
                            continue
                        kv = parse_pb(metric)
                        code = next((v for x, y, v in kv if x == 1 and y == 0), None)
                        value = next((v for x, y, v in kv if x == 2 and y == 0), None)
                        if code == 63 and value is not None:
                            tempos[player_id] = value
            for f,w,wrapper in group:
                if f!=5 or w!=2:continue
                outer=parse_pb(wrapper)
                player=next((v for k,t,v in outer if k==2 and t==2),None)
                if player is None:continue
                pf=parse_pb(player)
                pid=next((v for k,t,v in pf if k==1 and t==0),None)
                nb=next((v for k,t,v in pf if k==3 and t==2),None)
                if pid is None or nb is None:continue
                name=nb.decode('utf8').strip()
                if not name or len(name)>80 or not name.isprintable():continue
                job=next((v for k,t,v in pf if k==2 and t==0),0)
                power=next((v for k,t,v in pf if k==12 and t==0),None)
                if power is None:power=next((v for k,t,v in pf if k==11 and t==0),None)
                if pid not in stats:raise ValueError('Estatisticas ausentes para ID '+str(pid))
                typ,c=stats[pid]
                row={'Personagem':name,'Guilda':guilds.get(gid,'Não identificada'),
                     'Guilda_ID':gid,'2:4':job,'Power':power,'ID_Personagem':pid,
                     'Tipo_Estatisticas':typ,'_layout':'vigrid_salt','_match_id':match_id}
                for code,val in c.items():row['C:'+str(code)]=val
                if pid in tempos:
                    row['C:63'] = tempos[pid]
                    row['Minutos'] = round(tempos[pid] / 60, 1)
                rows.append(row)
        except (ValueError,StopIteration,UnicodeDecodeError) as exc:
            print("TEAM ERROR",repr(exc))
            continue
    return rows

def records_from_payload(blob):
    """Lê relatório clássico ou identifica o layout alternativo Vigrid/Salt."""
    try:
        root = parse_pb(blob)
        envelope = next(v for f, w, v in root if f == 2 and w == 2)
        match = parse_pb(envelope)
        # Layout alternativo Vigrid/Salt: relatório no campo 10.
        if any(f == 10 and w == 2 for f, w, v in match):
            return _parse_salt_report(blob)
        guild_names = {}
        for f, w, v in match:
            if f in (4, 5) and w == 2:
                info = parse_pb(v)
                name = next((x.decode('utf-8') for k, t, x in info if k == 3 and t == 2), None)
                guild_id = next((x for k, t, x in info if k == 5 and t == 0), None)
                if name and guild_id is not None:
                    guild_names[guild_id] = name
        data = next(v for f, w, v in match if f == 7 and w == 2)
        container = next(v for f, w, v in parse_pb(data) if f == 2 and w == 2)
        teams = [v for f, w, v in parse_pb(container) if f == 1 and w == 2]
    except (ValueError, StopIteration, UnicodeDecodeError):
        return []
    rows = []
    for team in teams:
        try:
            fields = parse_pb(team)
            guild_id = next(v for f, w, v in fields if f == 1 and w == 0)
            participants = next(v for f, w, v in fields if f == 2 and w == 2)
            player_blobs = [v for f, w, v in parse_pb(participants) if f == 1 and w == 2]
        except (ValueError, StopIteration):
            continue
        pending = [(v, 0) for v in player_blobs]
        while pending:
            player, depth = pending.pop()
            try:
                fields = parse_pb(player)
            except ValueError:
                continue
            names = []
            for f, w, v in fields:
                if f == 3 and w == 2 and 1 <= len(v) <= 80:
                    try:
                        name = v.decode('utf-8')
                        if name.isprintable() and name.strip(): names.append(name)
                    except UnicodeDecodeError:
                        pass
            numbers = {}
            for f, w, v in fields:
                if w == 2 and f in (1, 2) and len(v) < 24:
                    try:
                        pair = parse_pb(v)
                        if (len(pair) == 2 and pair[0][:2] == (1, 0)
                                and pair[1][:2] == (2, 0)):
                            key, value = pair[0][2], pair[1][2]
                            if value >= 2 ** 63: value -= 2 ** 64
                            numbers[f'{f}:{key}'] = value
                    except (ValueError, IndexError):
                        pass
            if names and len(numbers) >= 7 and '1:21' in numbers and '1:40' in numbers:
                rows.append({'Personagem': names[0], 'Guilda': guild_names.get(guild_id, 'Não identificada'),
                             'Guilda_ID': guild_id, **numbers})
            elif depth < 6:
                pending.extend((v, depth + 1) for f, w, v in fields if w == 2 and len(v) > 20)
    return rows

def find_reports(path):
    reports = []
    fingerprints = set()
    for flow, stream in tcp_streams(path):
        # Examina ambas as direcoes: a validacao do relatorio evita falsos positivos.
        pos = 0
        while pos + 4 <= len(stream):
            length = struct.unpack_from('<I', stream, pos)[0]
            if length < 8 or length > 8_000_000 or pos + 4 + length > len(stream):
                pos += 1  # Resync para capturas iniciadas no meio de uma mensagem
                continue
            message = stream[pos + 4:pos + 4 + length]
            pos += 4 + length
            if len(message) < 15 or message[4] != 5:
                continue
            # Envelopes observados no diagnostico4: cabeçalho 12 bytes + zlib.
            for off in (12, 8, 16):
                if len(message) <= off + 2 or message[off] != 0x78:
                    continue
                try:
                    raw = zlib.decompress(message[off:])
                except zlib.error:
                    continue
                if len(raw) > 4_000_000: continue
                rows = records_from_payload(raw)
                if len(rows) < 10: continue
                signature = (rows[0].get('_match_id'), rows[0].get('_layout')) if rows[0].get('_layout') == 'vigrid_salt' else tuple(sorted((r['Personagem'], r.get('1:21')) for r in rows))
                if signature not in fingerprints:
                    fingerprints.add(signature)
                    reports.append(rows)
                break
    return reports

def export_report(rows, folder, number=1):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    suffix = f'_{number}' if number > 1 else ''
    clean = folder / f'ROO_KDA{suffix}.csv'
    raw = folder / f'ROO_Campos_Completos{suffix}.csv'
    clean_columns = ['Personagem', 'Guilda', 'Guilda_ID', 'Job', 'Job_Codigo', 'Kills', 'Assistencias', 'Mortes', 'Ocupacoes', 'Pontuacao', 'Dano_Causado', 'Dano_Recebido', 'Cura', 'Pontos_Assistencias', 'Pontos_Mortes', 'Pontos_Ocupacoes']
    with clean.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=clean_columns, delimiter=';')
        writer.writeheader()
        for r in rows:
            writer.writerow({'Personagem': r['Personagem'], 'Guilda': r['Guilda'], 'Guilda_ID': r['Guilda_ID'], 'Job': job_from_code(r.get('2:4')), 'Job_Codigo': r.get('2:4', ''), 'Kills': r.get('1:0', 0),
                'Assistencias': r.get('1:40', 0), 'Mortes': r.get('1:1', 0), 'Ocupacoes': r.get('2:2', 0),
                'Pontuacao': r.get('1:21', 0), 'Dano_Causado': r.get('1:13', 0),
                'Dano_Recebido': r.get('1:12', 0), 'Cura': r.get('1:11', 0),
                'Pontos_Assistencias': r.get('2:19', 0), 'Pontos_Mortes': r.get('2:18', 0),
                'Pontos_Ocupacoes': r.get('2:20', 0)})
    extra_keys = set().union(*(r.keys() for r in rows)) - {'Personagem', 'Guilda', 'Guilda_ID', 'Job', 'Job_Codigo', '_layout'}
    fields = ['Personagem', 'Guilda', 'Guilda_ID', 'Job', 'Job_Codigo'] + sorted(
        extra_keys, key=lambda x: (0, tuple(map(int, x.split(':')))) if ':' in x and x.split(':')[0].isdigit() else (1, x))
    # Cabeçalhos legíveis, preservando o identificador original para auditoria.
    known = {
        '1:0': 'Kills', '1:40': 'Assistencias', '1:1': 'Mortes',
        '1:21': 'Pontuacao_Total', '1:13': 'Dano_Causado',
        '1:12': 'Dano_Recebido', '1:11': 'Cura_Realizada',
        '2:1': 'Pontuacao_Repetida', '2:2': 'Ocupacoes', '2:4': 'Job_Codigo',
        '2:19': 'Pontos_Assistencias', '2:18': 'Pontos_Mortes',
        '2:20': 'Pontos_Ocupacoes',
    }
    headers = {key: (f'{known[key]} ({key})' if key in known else f'Nao_Identificado ({key})')
               for key in fields if key != 'Personagem'}
    headers['Personagem'] = 'Personagem'
    headers['Guilda'] = 'Guilda'
    headers['Guilda_ID'] = 'Guilda_ID'
    headers['Job'] = 'Job'
    headers['Job_Codigo'] = 'Job_Codigo'
    with raw.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=[headers[k] for k in fields], delimiter=';')
        writer.writeheader()
        for r in rows:
            writer.writerow({headers[k]: v for k, v in {**r, 'Job': job_from_code(r.get('2:4')), 'Job_Codigo': r.get('2:4', '')}.items()})
    return clean, raw

def export_vigrid_diagnostic(rows, folder, number=1):
    """Exporta identidade e campos brutos para diagnóstico, sem fabricar métricas KDA."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    suffix = f'_{number}' if number > 1 else ''
    target = folder / f'ROO_Vigrid_Diagnostico{suffix}.csv'
    keys = sorted(set().union(*(r.keys() for r in rows)) - {'_layout'},
                  key=lambda x: (0, tuple(map(int, x.split(':')))) if ':' in x and x.split(':')[0].isdigit() else (1, x))
    columns = ['Personagem', 'Guilda', 'Guilda_ID', 'Job'] + [k for k in keys if k not in ('Personagem','Guilda','Guilda_ID')]
    with target.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=columns, delimiter=';')
        writer.writeheader()
        for r in rows:
            row = dict(r)
            row['Job'] = job_from_code(r.get('2:4'))
            writer.writerow({k: row.get(k, '') for k in columns})
    return target

def process(path, folder):
    reports = find_reports(path)
    if not reports:
        raise ValueError('Nenhum relatório KDA compatível foi identificado. Abra o KDA durante a captura.')
    results = []
    for index, rows in enumerate(reports, 1):
        if any(r.get('_layout') == 'vigrid_salt' for r in rows):
            diagnostic = export_vigrid_diagnostic(rows, folder, index)
            clean=Path(folder)/('Vigrid_157_Jogadores'+(('_'+str(index)) if index>1 else '')+'.csv')
            exportar_vigrid_csv(rows,clean)
            results.append((len(rows), clean, diagnostic))
        else:
            clean, raw = export_report(rows, folder, index)
            results.append((len(rows), clean, raw))
    return results

def _arquivo_chave_windows():
    """Chave criptografada pelo DPAPI do usuário Windows, fora da pasta do programa."""
    import os
    if os.name != 'nt':
        raise RuntimeError('O armazenamento seguro automático está disponível somente no Windows.')
    pasta = Path(os.environ.get('APPDATA', str(Path.home()))) / 'ROO_Classic'
    pasta.mkdir(parents=True, exist_ok=True)
    return pasta / 'chave_central.dpapi'


def _powershell_dpapi(comando, entrada):
    import subprocess
    # Dados sensíveis passam pelo stdin, nunca como argumento da linha de comando.
    r = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', comando],
                       input=entrada, text=True, capture_output=True, timeout=15,
                       encoding='utf-8')
    if r.returncode != 0:
        raise RuntimeError('Falha ao acessar a proteção de credenciais do Windows.')
    return r.stdout.strip()


def salvar_chave_windows(chave):
    # ConvertFrom-SecureString usa DPAPI por usuário no Windows.
    script = "$v=[Console]::In.ReadToEnd(); $s=ConvertTo-SecureString -String $v -AsPlainText -Force; ConvertFrom-SecureString -SecureString $s"
    protegida = _powershell_dpapi(script, chave)
    if not protegida:
        raise RuntimeError('O Windows não retornou a chave protegida.')
    _arquivo_chave_windows().write_text(protegida, encoding='utf-8')


def carregar_chave_windows():
    arquivo = _arquivo_chave_windows()
    if not arquivo.is_file():
        return ''
    script = "$v=[Console]::In.ReadToEnd(); $s=ConvertTo-SecureString -String $v; [System.Net.NetworkCredential]::new('', $s).Password"
    return _powershell_dpapi(script, arquivo.read_text(encoding='utf-8').strip())


def apagar_chave_windows():
    _arquivo_chave_windows().unlink(missing_ok=True)



# Vigrid: estatisticas de combate nao estao no pacote de cadastro/plantel
# capturado. Aceita uma tabela externa da MESMA partida, com valores verificados.
VIGRID_COLUMNS = ['Personagem','Guilda','Classe','Power','Partidas','Vitorias','Derrotas','Percentual_Vitorias','Kills','Mortes','Assistencias','KDA','Participacao','Dano_Causado','Dano_Por_Power','Dano_Recebido','Cura','Minutos','PP_Vigrid','GP','Merito','Ress','Mon','Titulos']
VIGRID_REQUIRED = ['Kills','Mortes','Assistencias','Dano_Causado','Dano_Recebido','Cura']

def exportar_modelo_vigrid(rows, destino):
    with open(destino,'w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=VIGRID_COLUMNS,delimiter=';')
        writer.writeheader()
        for r in sorted(rows,key=lambda x:(x['Guilda'],x['Personagem'].casefold())):
            writer.writerow({'Personagem':r['Personagem'],'Guilda':r['Guilda'],
                             'Classe':job_from_code(r.get('2:4')),
                             'Power':r.get('RAW:12','')})
    return destino

def _numero_vigrid(value,label):
    s=str(value).strip().replace(' ','')
    if not s: raise ValueError('Campo obrigatorio nao preenchido: '+label)
    # Valores completos em inteiros; nao aceita abreviacoes arredondadas da imagem.
    if not s.isdigit(): raise ValueError('Informe numero inteiro exato (sem mi/mil): '+label+' = '+s)
    return int(s)

def preparar_vigrid_csv(rows,csv_path,data,placar1='',placar2=''):
    if not rows or any(r.get('_layout')!='vigrid_salt' for r in rows):
        raise ValueError('Esta rotina e exclusiva da captura Vigrid/Salt.')
    roster={(r['Guilda'].casefold(),r['Personagem'].casefold()):r for r in rows}
    with open(csv_path,'r',encoding='utf-8-sig',newline='') as f:
        leitor=csv.DictReader(f,delimiter=';')
        if not leitor.fieldnames or any(k not in leitor.fieldnames for k in VIGRID_COLUMNS):
            raise ValueError('CSV precisa conter todas as colunas do modelo Vigrid.')
        preenchidos=[r for r in leitor if any(str(r.get(k,'')).strip() for k in VIGRID_REQUIRED)]
    if not preenchidos: raise ValueError('Nenhuma linha com KDA preenchido.')
    if len(preenchidos)!=len(roster):
        raise ValueError(f'Preencha todos os {len(roster)} jogadores da captura. Recebidos: {len(preenchidos)}. Nao importar parcialmente.')
    seen=set();jogadores=[]
    for r in preenchidos:
        key=(str(r['Guilda']).strip().casefold(),str(r['Personagem']).strip().casefold())
        if key not in roster:raise ValueError('Jogador/guilda nao existe na captura: '+str(key))
        if key in seen:raise ValueError('Jogador duplicado: '+r['Personagem'])
        seen.add(key)
        source=roster[key]
        power=_numero_vigrid(r['Power'],'Power de '+r['Personagem'])
        if power!=source.get('RAW:12'):
            raise ValueError('Power diferente da captura para '+r['Personagem'])
        p={'personagem':source['Personagem'],'guilda':source['Guilda'],
           'job':str(r['Classe']).strip() or job_from_code(source.get('2:4')),
           'job_codigo':source.get('2:4'),'power':power,
           'kills':_numero_vigrid(r['Kills'],'Kills'),
           'mortes':_numero_vigrid(r['Mortes'],'Mortes'),
           'assistencias':_numero_vigrid(r['Assistencias'],'Assistencias'),
           'dano_causado':_numero_vigrid(r['Dano_Causado'],'Dano_Causado'),
           'dano_recebido':_numero_vigrid(r['Dano_Recebido'],'Dano_Recebido'),
           'cura':_numero_vigrid(r['Cura'],'Cura'),
           'stats_extra':{k:r[k] for k in VIGRID_COLUMNS if k not in ['Personagem','Guilda','Classe','Power']}}
        jogadores.append(p)
    guilds=sorted({r['Guilda'] for r in rows if r['Guilda']!='Não identificada'})
    if len(guilds)!=2:raise ValueError('Esperadas duas guildas.')
    # hash inclui dados externos, evita confundir confrontos diferentes.
    signature=json.dumps({'data':data,'jogadores':sorted(jogadores,key=lambda p:(p['guilda'],p['personagem']))},sort_keys=True,ensure_ascii=False)
    digest=hashlib.sha256(signature.encode('utf8')).hexdigest()
    def score(s):return int(s) if str(s).strip() else None
    return {'guerra':{'id':'ROO-'+digest[:24],'mode':'vigrid_avenge','source_hash':digest,'data':data,
            'guilda1':guilds[0],'guilda2':guilds[1],'placar1':score(placar1),'placar2':score(placar2)},
            'jogadores':jogadores,'mapping_validated':True,'data_origin':'external_verified_csv'}

def preparar_vigrid_pcap(rows,data,placar1='',placar2=''):
    if not rows or any(r.get('_layout')!='vigrid_salt' for r in rows):
        raise ValueError('Captura nao e Vigrid/Salt.')
    if len(rows)<10:raise ValueError('Relatorio incompleto.')
    guilds=sorted({r['Guilda'] for r in rows})
    if len(guilds)!=2 or 'Não identificada' in guilds:
        raise ValueError('Duas guildas identificadas sao obrigatorias.')
    ids=[r['ID_Personagem'] for r in rows]
    if len(ids)!=len(set(ids)):raise ValueError('IDs de jogador duplicados.')
    mid=rows[0]['_match_id']
    if any(r['_match_id']!=mid for r in rows):raise ValueError('Partidas misturadas.')
    def c(r,k):return int(r.get('C:'+str(k),0) or 0)
    jogadores=[]
    for r in rows:
        mon=sum(c(r,k) for k in (20,23,51,65,66))
        merito=c(r,2)+c(r,18)+2*c(r,20)+10*c(r,23)+5*c(r,51)+2*c(r,65)+10*c(r,66)
        extras={'id_personagem':r['ID_Personagem'],'tipo_estatisticas':r['Tipo_Estatisticas'],
                'pp_vigrid':c(r,1),'gp':c(r,8),'merito':merito,'monstros':mon,
                'ressurreicoes':c(r,62),'min_individual':None,'titulos':None,
                'codigos_pcap':{k:v for k,v in r.items() if k.startswith('C:')}}
        jogadores.append({'personagem':r['Personagem'],'guilda':r['Guilda'],
            'job':job_from_code(r['2:4']),'job_codigo':r['2:4'],'power':r['Power'],
            'kills':c(r,2),'mortes':c(r,3),'assistencias':c(r,4),
            'dano_causado':c(r,64),'dano_recebido':c(r,71),'cura':c(r,48),
            'stats_extra':extras})
    signature=json.dumps({'mode':'vigrid_avenge','match_id':mid},sort_keys=True)
    digest=hashlib.sha256(signature.encode()).hexdigest()
    def score(v):return int(v) if str(v).strip() else None
    return {'guerra':{'id':'ROO-'+str(mid),'mode':'vigrid_avenge','source_hash':digest,
        'data':data,'guilda1':guilds[0],'guilda2':guilds[1],
        'placar1':score(placar1),'placar2':score(placar2)},
        'jogadores':jogadores,'mapping_validated':True,'data_origin':'pcap_verified_mapping'}


def exportar_vigrid_csv(rows,destino):
    import csv
    fields=['Personagem','Guilda','ID','Job','Power','K','D','A','Dano','Bear','Cura','PP Vigrid','GP','Mérito','Mon','Ress','Min','Títulos']
    with open(destino,'w',encoding='utf-8-sig',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=fields,delimiter=';');wr.writeheader()
        for r in rows:
            c=lambda k:int(r.get('C:'+str(k),0) or 0)
            wr.writerow({'Personagem':r['Personagem'],'Guilda':r['Guilda'],
              'ID':r['ID_Personagem'],'Job':job_from_code(r['2:4']),'Power':r['Power'],
              'K':c(2),'D':c(3),'A':c(4),'Dano':c(64),'Bear':c(71),'Cura':c(48),
              'PP Vigrid':c(1),'GP':c(8),'Mérito':c(2)+c(18)+2*c(20)+10*c(23)+5*c(51)+2*c(65)+10*c(66),
              'Mon':sum(c(k) for k in (20,23,51,65,66)),'Ress':c(62),
              'Min':'','Títulos':''})

def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    root = tk.Tk()
    root.title('ROO Classic | Extrator HIVE D1 v3.0')
    root.geometry('740x720')
    root.minsize(590, 350)
    root.configure(bg='#111827')
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('TButton', padding=10, font=('Segoe UI', 10))
    filevar = tk.StringVar()
    outvar = tk.StringVar(value=str(Path.home() / 'Documents' / 'ROO_Exportacoes'))
    def label(text, size=10, bold=False):
        tk.Label(root, text=text, fg='#e5e7eb', bg='#111827',
                 font=('Segoe UI', size, 'bold' if bold else 'normal'), anchor='w').pack(fill='x', padx=25, pady=(12, 3))
    label('RAGNAROK ORIGIN CLASSIC  •  EXTRATOR KDA', 16, True)
    label('Selecione o arquivo .pcapng capturado no Wireshark.')
    line = tk.Frame(root, bg='#111827'); line.pack(fill='x', padx=25)
    ttk.Entry(line, textvariable=filevar).pack(side='left', fill='x', expand=True)
    ttk.Button(line, text='Procurar...', command=lambda: filevar.set(filedialog.askopenfilename(filetypes=[('Capturas Wireshark', '*.pcapng'), ('Todos', '*.*')]))).pack(side='left', padx=(8,0))
    label('Pasta onde os arquivos CSV serão salvos:')
    line2 = tk.Frame(root, bg='#111827'); line2.pack(fill='x', padx=25)
    ttk.Entry(line2, textvariable=outvar).pack(side='left', fill='x', expand=True)
    ttk.Button(line2, text='Escolher...', command=lambda: outvar.set(filedialog.askdirectory() or outvar.get())).pack(side='left', padx=(8,0))
    status = tk.StringVar(value='Pronto. Extração local; gravação no D1 somente ao clicar em enviar.')
    tk.Label(root, textvariable=status, bg='#111827', fg='#93c5fd', font=('Segoe UI', 10),
             justify='left', anchor='w', wraplength=610).pack(fill='x', padx=25, pady=18)
    def run():
        try:
            if not Path(filevar.get()).is_file(): raise ValueError('Selecione um arquivo .pcapng válido.')
            status.set('Processando captura...')
            root.update_idletasks()
            results = process(filevar.get(), outvar.get())
            total = sum(n for n, _, _ in results)
            status.set(f'Sucesso! {len(results)} relatório(s), {total} registros. Arquivos em: {outvar.get()}')
            messagebox.showinfo('Extração concluída', f'{len(results)} relatório(s) extraído(s), {total} registros.\n\nArquivos CSV salvos em:\n{outvar.get()}')
        except Exception as e:
            status.set(f'Não foi possível extrair: {e}')
            messagebox.showerror('Erro', str(e))
    ttk.Button(root, text='EXTRAIR KDA E GERAR CSV', command=run).pack(pady=8)

    label('CENTRAL DE GUERRA HIVE  •  Cloudflare D1', 12, True)
    label('Chave privada (não envie em prints nem mensagens):')
    tokenvar = tk.StringVar()
    ttk.Entry(root, textvariable=tokenvar, show='*').pack(fill='x', padx=25)
    guardarvar = tk.BooleanVar(value=True)
    ttk.Checkbutton(root, text='Lembrar chave neste Windows (criptografada para meu usuário)',
                    variable=guardarvar).pack(anchor='w', padx=25, pady=5)
    def limpar_chave():
        try:
            apagar_chave_windows()
            tokenvar.set('')
            guardarvar.set(False)
            messagebox.showinfo('Chave removida', 'A chave salva neste computador foi apagada.')
        except Exception as exc:
            messagebox.showerror('Erro', str(exc))
    ttk.Button(root, text='Esquecer chave salva', command=limpar_chave).pack(anchor='w', padx=25)
    try:
        chave_salva = carregar_chave_windows()
        if chave_salva:
            tokenvar.set(chave_salva)
    except Exception:
        guardarvar.set(False)
        # O usuário pode inserir novamente a chave; nunca mostrar seu conteúdo no erro.
    label('Data da guerra (AAAA-MM-DD; opcional):')
    datavar = tk.StringVar()
    ttk.Entry(root, textvariable=datavar).pack(fill='x', padx=25)
    label('Placar (opcional; ordem alfabética das guildas):')
    placar1var = tk.StringVar()
    placar2var = tk.StringVar()
    line3=tk.Frame(root,bg='#111827');line3.pack(fill='x',padx=25)
    ttk.Entry(line3,textvariable=placar1var).pack(side='left',fill='x',expand=True)
    ttk.Entry(line3,textvariable=placar2var).pack(side='left',fill='x',expand=True,padx=(10,0))
    def enviar():
        try:
            if not Path(filevar.get()).is_file(): raise ValueError('Selecione um .pcapng.')
            token=tokenvar.get().strip()
            if not token: raise ValueError('Informe a chave HIVE_WAR_IMPORT_KEY do Cloudflare.')
            data=datavar.get().strip()
            if not data: raise ValueError('Informe a data da guerra (AAAA-MM-DD).')
            import datetime
            datetime.date.fromisoformat(data)
            reports=find_reports(filevar.get())
            if len(reports)!=1:
                raise ValueError(f'Encontrados {len(reports)} relatórios. Envie uma captura contendo somente uma guerra.')
            if reports[0][0].get('_layout') == 'vigrid_salt':
                payload=preparar_vigrid_pcap(reports[0],data,placar1var.get().strip(),placar2var.get().strip())
            else:
                payload=preparar_envio(reports[0],token,data,placar1var.get().strip(),placar2var.get().strip())
            g=payload['guerra']
            resumo=f"{g['guilda1']} × {g['guilda2']} | {len(payload['jogadores'])} jogadores | {len(payload.get('campos',[]))} campos extras"
            if not messagebox.askyesno('Confirmar envio', resumo+'\n\nEnviar para o banco Cloudflare D1?'): return
            status.set('Enviando para a Central de Guerra...')
            root.update_idletasks()
            resposta=enviar_central(payload,token)
            if guardarvar.get():
                try:
                    salvar_chave_windows(token)
                except Exception:
                    messagebox.showwarning('Chave não salva',
                        'Envio concluído, mas não foi possível proteger a chave no Windows. Será necessário digitá-la novamente.')
            msg=('Esta guerra já estava importada; nenhum dado foi duplicado.' if resposta.get('duplicado')
                 else 'Guerra enviada com sucesso!')
            status.set(msg+' ID: '+g['id'])
            messagebox.showinfo('Central de Guerra',msg+'\n\n'+resumo+'\nID: '+g['id'])
        except Exception as exc:
            status.set('Falha no envio: '+str(exc))
            messagebox.showerror('Falha no envio',str(exc))
    def modelo_salt():
        try:
            reports=find_reports(filevar.get())
            if len(reports)!=1 or reports[0][0].get('_layout')!='vigrid_salt':
                raise ValueError('Selecione uma captura Salt com uma guerra.')
            destino=filedialog.asksaveasfilename(title='Salvar modelo Vigrid',defaultextension='.csv',initialfile='Vigrid_Preencher.csv',filetypes=[('CSV','*.csv')])
            if destino:
                exportar_modelo_vigrid(reports[0],destino)
                messagebox.showinfo('Modelo gerado','Modelo auxiliar gerado. O envio Vigrid agora usa diretamente o PCAP.')
        except Exception as exc:messagebox.showerror('Modelo Vigrid',str(exc))
    ttk.Button(root,text='GERAR MODELO CSV VIGRID',command=modelo_salt).pack(pady=6)
    ttk.Button(root,text='ENVIAR PARA CENTRAL DE GUERRA',command=enviar).pack(pady=12)

    tk.Label(root, text='Sugar e Vigrid: envio direto do PCAP. Min individual e Titulos ficam em branco.',
             fg='#9ca3af', bg='#111827', font=('Segoe UI', 9)).pack(pady=8)
    root.mainloop()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        src = sys.argv[1]
        dest = sys.argv[2] if len(sys.argv) >= 3 else str(Path(src).parent / 'ROO_Exportacoes')
        for n, clean, raw in process(src, dest):
            print(f'{n} jogadores: {clean} | {raw}')
    else:
        gui()
