# Generates camera-like test frames for the QR scanner (tools/qrscan/run.sh).
# Needs: pip install segno pillow
# Each case: 640x480 grey frame, blur, optional mirror; plus rotated, flipped
# and damaged variants (dark/light blots the Reed-Solomon code must repair).
import segno, random, sys, os
from PIL import Image, ImageFilter
out=sys.argv[1]
random.seed(1)
words="ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom"
W=[words[i:i+4] for i in range(0,len(words),4)]
def bw(n): return "".join(random.choice(W)[0]+random.choice(W)[-1] for _ in range(n))
cases=[]
i=0
for upper in (False,True):
  for ecc in "lmqh":
    for frag in (60,120,200):
      s=f"ur:xmr-output/{random.randint(1,999)}-{random.randint(100,999)}/"+bw(frag+30)
      if upper: s=s.upper()
      for mirror in (False,True):
        cases.append((i,s,ecc,mirror)); i+=1
for i,s,ecc,mirror in cases:
    try:
        q=segno.make_qr(s, error=ecc, boost_error=False)
    except Exception as e:
        print("skip",i,e); continue
    if q.version>20: print("skip v",i,q.version); continue
    scale=4
    path=f"{out}/c{i}.png"
    q.save(path, scale=scale, border=4, dark="black", light="white")
    im=Image.open(path).convert("L")
    # put into a larger photo-like frame, slight blur, grey levels
    W_,H_=640,480
    if im.width>W_-20: 
        s2=(W_-20)/im.width; im=im.resize((int(im.width*s2),int(im.height*s2)))
    bg=Image.new("L",(W_,H_),110)
    bg.paste(im.point(lambda p: 30 if p<128 else 220),((W_-im.width)//2,(H_-im.height)//2))
    bg=bg.filter(ImageFilter.GaussianBlur(0.8))
    if mirror: bg=bg.transpose(Image.FLIP_LEFT_RIGHT)
    bg.save(f"{out}/c{i}.pgm")
    open(f"{out}/c{i}.txt","w").write(f"{q.version} {ecc} {int(mirror)} {q.mode}\n{s}\n")
    os.remove(path)
print(len(cases))

from PIL import ImageDraw
random.seed(7)
for i,s,ecc,mirror in cases:
    p=f"{out}/c{i}.pgm"
    if not os.path.exists(p): continue
    base=Image.open(p); meta=open(f"{out}/c{i}.txt").read()
    for tag,img in (("r90",base.transpose(Image.ROTATE_90).crop((-80,80,560,560))),("r180",base.transpose(Image.ROTATE_180)),
                    ("flipv",base.transpose(Image.FLIP_TOP_BOTTOM))):
        img.save(f"{out}/c{i}{tag}.pgm"); open(f"{out}/c{i}{tag}.txt","w").write(meta)
    dmg=base.copy(); d=ImageDraw.Draw(dmg)
    for _ in range(6):
        x=random.randint(250,390); y=random.randint(170,310)
        d.rectangle([x,y,x+5,y+5], fill=random.choice([30,220]))
    dmg.save(f"{out}/c{i}dmg.pgm"); open(f"{out}/c{i}dmg.txt","w").write(meta)
