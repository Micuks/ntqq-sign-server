// ===== sub_56C46C0 @ 0x56c46c0 (size 0xa32a) =====
void **__fastcall sub_56C46C0(void **a1, const char *a2, __int64 *a3, _QWORD *a4)
{
  void *v4; // rax
  __int128 **v5; // rax
  bool v6; // zf
  size_t v7; // rax
  __int64 v8; // rax
  void *v9; // rbx
  __int64 v10; // rax
  __int64 v11; // rax
  unsigned int v12; // ecx
  int v13; // eax
  int i; // ecx
  __int64 v15; // rcx
  int v16; // r10d
  int v17; // r11d
  int v18; // r9d
  int v19; // r8d
  unsigned int v20; // esi
  int v21; // edx
  int n; // eax
  int v23; // esi
  unsigned int j; // edx
  int k; // esi
  int v26; // r11d
  int v27; // r9d
  int v28; // r8d
  int v29; // edi
  unsigned int v30; // edx
  int v31; // ecx
  int m; // eax
  int v33; // edx
  int v34; // ecx
  int v35; // edx
  int v36; // edi
  int v37; // ebp
  int v38; // ecx
  int v39; // edx
  int v40; // eax
  int v41; // r11d
  int v42; // ebx
  int v43; // edx
  int v44; // r12d
  int v45; // r13d
  int v46; // ebx
  int v47; // ecx
  int v48; // edx
  int v49; // r8d
  int v50; // r13d
  int v51; // r14d
  int v52; // edx
  int v53; // r11d
  int v54; // r13d
  int v55; // r8d
  int v56; // edx
  int v57; // ebx
  int v58; // r13d
  int v59; // r11d
  int v60; // edx
  int v61; // r8d
  int v62; // ebx
  int v63; // r11d
  int v64; // r15d
  int v65; // ecx
  int v66; // r8d
  int v67; // ebx
  int v68; // r11d
  int v69; // edx
  int v70; // r15d
  int v71; // r8d
  int v72; // ecx
  int v73; // r13d
  int v74; // r14d
  int v75; // ebx
  int v76; // r11d
  int v77; // r8d
  int v78; // edx
  int v79; // ebx
  int v80; // r13d
  int v81; // r11d
  int v82; // edx
  int v83; // ebx
  int v84; // r8d
  int v85; // ebp
  int v86; // eax
  int v87; // edx
  int v88; // ebx
  int v89; // esi
  int v90; // ebp
  int v91; // ecx
  int v92; // ebx
  int v93; // edx
  int v94; // esi
  int v95; // ecx
  int v96; // eax
  unsigned int v97; // eax
  int v98; // ecx
  int v99; // ecx
  int v100; // edx
  int v101; // ebp
  int v102; // ebx
  int v103; // ecx
  int v104; // edx
  int v105; // ebp
  int v106; // ebx
  int v107; // ecx
  int v108; // edx
  int v109; // r8d
  int v110; // r15d
  int v111; // eax
  int v112; // r10d
  int v113; // edx
  int v114; // edi
  int v115; // eax
  int v116; // ecx
  int v117; // r10d
  int v118; // edx
  int v119; // eax
  int v120; // r15d
  int v121; // ecx
  int v122; // edx
  int v123; // eax
  int v124; // r15d
  int v125; // r10d
  int v126; // edx
  int v127; // ecx
  int v128; // eax
  int v129; // r10d
  int v130; // edx
  int v131; // esi
  int v132; // eax
  int v133; // ecx
  int v134; // r15d
  int v135; // edx
  int v136; // esi
  int v137; // r10d
  int v138; // eax
  int v139; // r15d
  int v140; // ecx
  int v141; // edx
  int v142; // r10d
  int v143; // eax
  int v144; // ecx
  int v145; // edx
  int v146; // r15d
  int v147; // r10d
  int v148; // ecx
  int v149; // edx
  int v150; // ebp
  int v151; // eax
  int v152; // ecx
  int v153; // edx
  int v154; // ebx
  int v155; // edi
  int v156; // ebp
  int v157; // ecx
  int v158; // ebx
  int v159; // eax
  int v160; // esi
  int v161; // ecx
  int v162; // edx
  int v163; // eax
  unsigned int v164; // eax
  int v165; // ecx
  unsigned int ii; // edx
  int jj; // esi
  unsigned int v168; // ecx
  int v169; // eax
  int kk; // edx
  int v171; // ecx
  int v172; // eax
  int mm; // ecx
  int v174; // ebx
  unsigned int v175; // r10d
  int v176; // r9d
  int v177; // r8d
  unsigned int v178; // edi
  int v179; // esi
  int i3; // ecx
  int v181; // esi
  unsigned int nn; // edx
  int i1; // esi
  int v184; // r10d
  int v185; // r8d
  unsigned int v186; // r9d
  int v187; // edi
  unsigned int v188; // ecx
  int v189; // eax
  int i2; // edx
  int v191; // edx
  int v192; // eax
  int v193; // ecx
  int v194; // esi
  int v195; // edi
  int v196; // eax
  int v197; // ecx
  int v198; // esi
  int v199; // ebx
  int v200; // eax
  int v201; // ecx
  int v202; // edx
  int v203; // r12d
  int v204; // r9d
  int v205; // eax
  int v206; // r11d
  int v207; // ecx
  int v208; // ebp
  int v209; // eax
  int v210; // r11d
  int v211; // r12d
  int v212; // ecx
  int v213; // eax
  int v214; // r9d
  int v215; // r12d
  int v216; // ecx
  int v217; // r11d
  int v218; // edx
  int v219; // r9d
  int v220; // ebp
  int v221; // ecx
  int v222; // r15d
  int v223; // edx
  int v224; // r9d
  int v225; // ecx
  int v226; // r11d
  int v227; // ebp
  int v228; // r9d
  int v229; // edx
  int v230; // r15d
  int v231; // r11d
  int v232; // eax
  int v233; // r14d
  int v234; // r9d
  int v235; // ebp
  int v236; // edx
  int v237; // r15d
  int v238; // eax
  int v239; // ebp
  int v240; // r11d
  int v241; // ecx
  int v242; // r8d
  int v243; // esi
  int v244; // ebp
  int v245; // ecx
  int v246; // ebx
  int v247; // r8d
  int v248; // edx
  int v249; // ebp
  int v250; // eax
  int v251; // ebx
  int v252; // edx
  int v253; // esi
  int v254; // eax
  int v255; // ecx
  unsigned int v256; // eax
  int v257; // ecx
  unsigned int v258; // eax
  unsigned int v259; // ecx
  unsigned int v260; // ebx
  unsigned int v261; // ebp
  unsigned int v262; // eax
  unsigned int v263; // ecx
  int v264; // ebx
  int v265; // ebp
  int v266; // eax
  int v267; // edx
  int v268; // r13d
  int v269; // ecx
  int v270; // esi
  int v271; // eax
  int v272; // edx
  int v273; // ecx
  int v274; // esi
  int v275; // r8d
  int v276; // edx
  int v277; // eax
  int v278; // esi
  int v279; // ecx
  int v280; // edx
  int v281; // eax
  int v282; // esi
  int v283; // r8d
  int v284; // edx
  int v285; // ecx
  int v286; // esi
  int v287; // eax
  int v288; // edx
  int v289; // r8d
  int v290; // esi
  int v291; // ecx
  int v292; // eax
  int v293; // edx
  int v294; // esi
  int v295; // ecx
  int v296; // eax
  int v297; // edx
  int v298; // esi
  int v299; // ecx
  int v300; // eax
  int v301; // edx
  int v302; // esi
  int v303; // ecx
  int v304; // eax
  int v305; // edx
  int v306; // r8d
  int v307; // ecx
  int v308; // esi
  int v309; // r9d
  int v310; // edx
  int v311; // ecx
  int v312; // esi
  int v313; // edi
  int v314; // r8d
  int v315; // ebx
  int v316; // eax
  int v317; // edx
  int v318; // ebp
  int v319; // esi
  int v320; // eax
  int v321; // ecx
  int v322; // ebp
  unsigned int v323; // eax
  int v324; // ecx
  unsigned int i4; // edx
  int i5; // esi
  unsigned int v327; // eax
  int i6; // ecx
  char *v329; // rax
  int v330; // r11d
  int v331; // ebp
  unsigned int v332; // r9d
  int v333; // r8d
  unsigned int v334; // edx
  int v335; // ecx
  int i10; // esi
  int v337; // esi
  unsigned int i7; // edx
  int i8; // esi
  int v340; // r8d
  unsigned int v341; // ebp
  int v342; // r10d
  int v343; // edi
  unsigned int v344; // ecx
  int v345; // eax
  int i9; // edx
  int v347; // edx
  unsigned int v348; // eax
  unsigned int v349; // ecx
  unsigned int v350; // edx
  unsigned int v351; // esi
  unsigned int v352; // eax
  unsigned int v353; // ecx
  int v354; // edx
  int v355; // ebp
  int v356; // eax
  int v357; // ecx
  int v358; // r12d
  int v359; // r13d
  int v360; // edi
  int v361; // eax
  int v362; // ecx
  int v363; // ebx
  int v364; // r8d
  int v365; // eax
  int v366; // ecx
  int v367; // r13d
  int v368; // r8d
  int v369; // eax
  int v370; // ecx
  int v371; // r10d
  int v372; // ebx
  int v373; // eax
  int v374; // ecx
  int v375; // r8d
  int v376; // ebx
  int v377; // eax
  int v378; // r11d
  int v379; // ecx
  int v380; // r10d
  int v381; // edi
  int v382; // r8d
  int v383; // ebx
  int v384; // ecx
  int v385; // eax
  int v386; // r13d
  int v387; // r8d
  int v388; // ecx
  int v389; // eax
  int v390; // r10d
  int v391; // r8d
  int v392; // ecx
  int v393; // eax
  int v394; // ebx
  int v395; // r8d
  int v396; // ecx
  int v397; // r10d
  int v398; // edx
  int v399; // ebx
  int v400; // ecx
  int v401; // edi
  int v402; // ebp
  int v403; // edx
  int v404; // ebx
  int v405; // eax
  int v406; // ebp
  int v407; // edx
  int v408; // esi
  int v409; // eax
  int v410; // ecx
  unsigned int v411; // eax
  int v412; // ecx
  int v413; // eax
  int v414; // ecx
  int v415; // edx
  int v416; // edi
  int v417; // ebx
  int v418; // ecx
  int v419; // edx
  int v420; // ebp
  int v421; // eax
  int v422; // ecx
  int v423; // r12d
  int v424; // r13d
  int v425; // ebx
  int v426; // eax
  int v427; // ecx
  int v428; // r13d
  int v429; // r8d
  int v430; // r9d
  int v431; // ecx
  int v432; // r13d
  int v433; // r8d
  int v434; // r9d
  int v435; // ecx
  int v436; // ebx
  int v437; // r8d
  int v438; // r9d
  int v439; // ecx
  int v440; // r13d
  int v441; // ebx
  int v442; // r9d
  int v443; // r8d
  int v444; // ecx
  int v445; // r11d
  int v446; // ebx
  int v447; // r8d
  int v448; // ecx
  int v449; // r13d
  int v450; // ebx
  int v451; // r9d
  int v452; // r11d
  int v453; // eax
  int v454; // r8d
  int v455; // r9d
  int v456; // ecx
  int v457; // r13d
  int v458; // r11d
  int v459; // ebx
  int v460; // r8d
  int v461; // ecx
  int v462; // r15d
  int v463; // r9d
  int v464; // ebx
  int v465; // ecx
  int v466; // ebp
  int v467; // eax
  int v468; // ebx
  int v469; // esi
  int v470; // ebp
  int v471; // ecx
  int v472; // edx
  int v473; // esi
  int v474; // eax
  int v475; // ecx
  int v476; // edx
  unsigned int v477; // eax
  int v478; // ecx
  unsigned int i11; // esi
  int i12; // edi
  unsigned int v481; // ecx
  int v482; // eax
  int i13; // edx
  unsigned int v484; // eax
  int v485; // ecx
  int i14; // eax
  unsigned int i15; // ecx
  int i16; // edx
  unsigned int v489; // eax
  int i17; // ecx
  char *v491; // rax
  int v492; // r11d
  int v493; // r9d
  int v494; // r10d
  unsigned int v495; // r8d
  unsigned int v496; // esi
  int v497; // edx
  int i21; // ecx
  int v499; // esi
  unsigned int i18; // edx
  int i19; // esi
  int v502; // r9d
  int v503; // r10d
  int v504; // r8d
  unsigned int v505; // edi
  unsigned int v506; // edx
  int v507; // eax
  int i20; // ecx
  int v509; // edx
  int v510; // eax
  int v511; // edx
  int v512; // edi
  int v513; // ebx
  int v514; // eax
  int v515; // edx
  int v516; // edi
  int v517; // ebp
  int v518; // ecx
  int v519; // r8d
  int v520; // r15d
  int v521; // r12d
  int v522; // r9d
  int v523; // r8d
  int v524; // r11d
  int v525; // edx
  int v526; // r14d
  int v527; // r13d
  int v528; // r12d
  int v529; // r11d
  int v530; // r8d
  int v531; // edx
  int v532; // r12d
  int v533; // r11d
  int v534; // r8d
  int v535; // r13d
  int v536; // r14d
  int v537; // r11d
  int v538; // edx
  int v539; // r8d
  int v540; // r14d
  int v541; // r13d
  int v542; // r11d
  int v543; // r12d
  int v544; // r8d
  int v545; // r14d
  int v546; // r13d
  int v547; // r11d
  int v548; // edx
  int v549; // r12d
  int v550; // r8d
  int v551; // r11d
  int v552; // r14d
  int v553; // edx
  int v554; // r8d
  int v555; // r12d
  int v556; // r14d
  int v557; // r11d
  int v558; // r8d
  int v559; // esi
  int v560; // ebp
  int v561; // edx
  int v562; // r8d
  int v563; // eax
  int v564; // ebp
  int v565; // esi
  int v566; // r8d
  int v567; // eax
  int v568; // ebx
  int v569; // ecx
  int v570; // esi
  int v571; // eax
  int v572; // edx
  unsigned int v573; // eax
  int v574; // ecx
  int v575; // eax
  int v576; // edx
  int v577; // ebp
  int v578; // ebx
  int v579; // eax
  int v580; // edx
  int v581; // ebp
  int v582; // ebx
  int v583; // ecx
  int v584; // edx
  int v585; // r15d
  int v586; // r10d
  int v587; // r8d
  int v588; // r11d
  int v589; // eax
  int v590; // ebx
  int v591; // r10d
  int v592; // r11d
  int v593; // edx
  int v594; // r14d
  int v595; // r10d
  int v596; // ebx
  int v597; // edx
  int v598; // r14d
  int v599; // r10d
  int v600; // r11d
  int v601; // edx
  int v602; // r14d
  int v603; // ebx
  int v604; // r10d
  int v605; // r11d
  int v606; // edx
  int v607; // r14d
  int v608; // r8d
  int v609; // r11d
  int v610; // ebx
  int v611; // r12d
  int v612; // r10d
  int v613; // edx
  int v614; // r14d
  int v615; // ebx
  int v616; // r10d
  int v617; // r11d
  int v618; // r14d
  int v619; // ebx
  int v620; // edx
  int v621; // r10d
  int v622; // r14d
  int v623; // ebx
  int v624; // r11d
  int v625; // r10d
  int v626; // edx
  int v627; // eax
  int v628; // ebp
  int v629; // r8d
  int v630; // ebx
  int v631; // r10d
  int v632; // eax
  int v633; // ebp
  int v634; // ecx
  int v635; // esi
  int v636; // eax
  int v637; // edx
  int v638; // ecx
  unsigned int v639; // eax
  int v640; // ecx
  unsigned int i22; // edx
  int i23; // esi
  unsigned int v643; // ecx
  int v644; // eax
  int i24; // edx
  int v646; // ecx
  int v647; // eax
  int i25; // ecx
  int v649; // r11d
  int v650; // r9d
  unsigned int v651; // r10d
  int v652; // r8d
  unsigned int v653; // edx
  int v654; // ecx
  int i29; // esi
  int v656; // esi
  unsigned int i26; // edx
  int i27; // esi
  unsigned int v659; // r11d
  int v660; // ebx
  int v661; // r8d
  int v662; // edi
  unsigned int v663; // ecx
  int v664; // eax
  int i28; // edx
  int v666; // edx
  int v667; // eax
  int v668; // ecx
  int v669; // ebp
  int v670; // ebx
  int v671; // edi
  int v672; // edx
  int v673; // ecx
  int v674; // ebx
  int v675; // edi
  int v676; // eax
  int v677; // ecx
  int v678; // r8d
  int v679; // r12d
  int v680; // ebp
  int v681; // eax
  int v682; // edx
  int v683; // esi
  int v684; // ebp
  int v685; // r12d
  int v686; // eax
  int v687; // edx
  int v688; // r11d
  int v689; // r12d
  int v690; // eax
  int v691; // edx
  int v692; // ebp
  int v693; // r12d
  int v694; // r11d
  int v695; // edx
  int v696; // eax
  int v697; // ebp
  int v698; // r11d
  int v699; // edx
  int v700; // eax
  int v701; // r12d
  int v702; // ebp
  int v703; // edx
  int v704; // eax
  int v705; // r11d
  int v706; // ebp
  int v707; // edx
  int v708; // r12d
  int v709; // eax
  int v710; // r11d
  int v711; // edx
  int v712; // ebp
  int v713; // r12d
  int v714; // eax
  int v715; // edx
  int v716; // r11d
  int v717; // ebp
  int v718; // r12d
  int v719; // edi
  int v720; // eax
  int v721; // r11d
  int v722; // ebp
  int v723; // esi
  int v724; // edx
  int v725; // ebx
  int v726; // eax
  int v727; // ebp
  int v728; // edx
  int v729; // esi
  int v730; // eax
  int v731; // ecx
  unsigned int v732; // eax
  int v733; // ecx
  int v734; // eax
  int v735; // edi
  int v736; // ebx
  int v737; // ebp
  int v738; // eax
  int v739; // esi
  int v740; // ebx
  int v741; // ebp
  int v742; // eax
  int v743; // r15d
  int v744; // ecx
  int v745; // r10d
  int v746; // ebp
  int v747; // r12d
  int v748; // ecx
  int v749; // r10d
  int v750; // r11d
  int v751; // r12d
  int v752; // ebp
  int v753; // r10d
  int v754; // r11d
  int v755; // r8d
  int v756; // ebp
  int v757; // r10d
  int v758; // r11d
  int v759; // r12d
  int v760; // ebp
  int v761; // r8d
  int v762; // r11d
  int v763; // r10d
  int v764; // r12d
  int v765; // ebp
  int v766; // r11d
  int v767; // r8d
  int v768; // r10d
  int v769; // r14d
  int v770; // r11d
  int v771; // ebp
  int v772; // r8d
  int v773; // r10d
  int v774; // r12d
  int v775; // r14d
  int v776; // ebp
  int v777; // r11d
  int v778; // r12d
  int v779; // r8d
  int v780; // r10d
  int v781; // r11d
  int v782; // r14d
  int v783; // r12d
  int v784; // r10d
  int v785; // ebp
  int v786; // r11d
  int v787; // ebx
  int v788; // r10d
  int v789; // edx
  int v790; // r8d
  int v791; // eax
  int v792; // ebx
  int v793; // edx
  int v794; // esi
  int v795; // eax
  int v796; // ecx
  int v797; // edx
  unsigned int v798; // eax
  int v799; // ecx
  unsigned int i30; // edx
  int i31; // esi
  unsigned int v802; // eax
  int i32; // ecx
  char *v804; // rax
  int v805; // r10d
  int v806; // ebp
  int v807; // r9d
  unsigned int v808; // r8d
  unsigned int v809; // edx
  int v810; // ecx
  int i36; // esi
  int v812; // esi
  unsigned int i33; // edx
  int i34; // esi
  int v815; // r8d
  unsigned int v816; // r10d
  int v817; // r9d
  int v818; // edi
  unsigned int v819; // ecx
  int v820; // eax
  int i35; // edx
  int v822; // edx
  unsigned int v823; // eax
  unsigned int v824; // ecx
  unsigned int v825; // edx
  unsigned int v826; // esi
  unsigned int v827; // eax
  unsigned int v828; // ecx
  int v829; // edx
  int v830; // ebp
  int v831; // eax
  int v832; // ecx
  int v833; // r12d
  int v834; // r13d
  int v835; // edi
  int v836; // eax
  int v837; // ecx
  int v838; // ebx
  int v839; // r8d
  int v840; // eax
  int v841; // ecx
  int v842; // r13d
  int v843; // r8d
  int v844; // eax
  int v845; // ecx
  int v846; // r9d
  int v847; // ebx
  int v848; // eax
  int v849; // ecx
  int v850; // r8d
  int v851; // ebx
  int v852; // eax
  int v853; // r10d
  int v854; // ecx
  int v855; // r9d
  int v856; // edi
  int v857; // r8d
  int v858; // ebx
  int v859; // ecx
  int v860; // eax
  int v861; // r13d
  int v862; // r8d
  int v863; // ecx
  int v864; // eax
  int v865; // r9d
  int v866; // r8d
  int v867; // ecx
  int v868; // eax
  int v869; // ebx
  int v870; // r8d
  int v871; // ecx
  int v872; // r9d
  int v873; // edx
  int v874; // ebx
  int v875; // ecx
  int v876; // edi
  int v877; // ebp
  int v878; // edx
  int v879; // ebx
  int v880; // eax
  int v881; // ebp
  int v882; // edx
  int v883; // esi
  int v884; // eax
  int v885; // ecx
  unsigned int v886; // eax
  int v887; // ecx
  int v888; // eax
  int v889; // ecx
  int v890; // edx
  int v891; // edi
  int v892; // eax
  int v893; // ecx
  int v894; // edx
  int v895; // ebp
  int v896; // eax
  int v897; // ecx
  int v898; // r12d
  int v899; // r13d
  int v900; // ebx
  int v901; // eax
  int v902; // ecx
  int v903; // r13d
  int v904; // r9d
  int v905; // r8d
  int v906; // ecx
  int v907; // r13d
  int v908; // r9d
  int v909; // r8d
  int v910; // ecx
  int v911; // ebx
  int v912; // r9d
  int v913; // r8d
  int v914; // ecx
  int v915; // r13d
  int v916; // ebx
  int v917; // r9d
  int v918; // r8d
  int v919; // ecx
  int v920; // r10d
  int v921; // ebx
  int v922; // r9d
  int v923; // ecx
  int v924; // r13d
  int v925; // ebx
  int v926; // r8d
  int v927; // r10d
  int v928; // eax
  int v929; // r9d
  int v930; // r8d
  int v931; // ecx
  int v932; // r13d
  int v933; // r10d
  int v934; // ebx
  int v935; // r9d
  int v936; // ecx
  int v937; // r14d
  int v938; // r8d
  int v939; // ebx
  int v940; // ecx
  int v941; // ebp
  int v942; // eax
  int v943; // ebx
  int v944; // esi
  int v945; // ebp
  int v946; // ecx
  int v947; // edx
  int v948; // esi
  int v949; // eax
  int v950; // ecx
  int v951; // edx
  unsigned int v952; // eax
  int v953; // ecx
  unsigned int i37; // esi
  int i38; // edi
  unsigned int v956; // ecx
  int v957; // eax
  int i39; // edx
  unsigned int v959; // eax
  int v960; // ecx
  int i40; // eax
  unsigned int i41; // ecx
  int i42; // edx
  unsigned __int8 v965; // [rsp+Fh] [rbp-349h]
  void *v966; // [rsp+10h] [rbp-348h]
  void *v967; // [rsp+18h] [rbp-340h]
  unsigned int *v968; // [rsp+20h] [rbp-338h]
  _QWORD *v969; // [rsp+28h] [rbp-330h]
  _QWORD *v970; // [rsp+28h] [rbp-330h]
  _QWORD *v971; // [rsp+28h] [rbp-330h]
  _QWORD *v972; // [rsp+28h] [rbp-330h]
  unsigned int v973; // [rsp+34h] [rbp-324h]
  unsigned int v974; // [rsp+3Ch] [rbp-31Ch]
  void **v975; // [rsp+48h] [rbp-310h]
  unsigned int v976; // [rsp+54h] [rbp-304h]
  unsigned int v977; // [rsp+54h] [rbp-304h]
  _QWORD *v978; // [rsp+60h] [rbp-2F8h]
  _QWORD *v979; // [rsp+60h] [rbp-2F8h]
  _QWORD *v980; // [rsp+60h] [rbp-2F8h]
  int v981; // [rsp+90h] [rbp-2C8h]
  int v982; // [rsp+98h] [rbp-2C0h]
  int v983; // [rsp+98h] [rbp-2C0h]
  int v984; // [rsp+98h] [rbp-2C0h]
  void **v985; // [rsp+A0h] [rbp-2B8h]
  unsigned int v986; // [rsp+A0h] [rbp-2B8h]
  unsigned int v987; // [rsp+A0h] [rbp-2B8h]
  unsigned int v988; // [rsp+A0h] [rbp-2B8h]
  void *v989; // [rsp+A8h] [rbp-2B0h]
  int v990; // [rsp+C0h] [rbp-298h]
  int v991; // [rsp+D0h] [rbp-288h]
  int v992; // [rsp+D0h] [rbp-288h]
  int v993; // [rsp+D0h] [rbp-288h]
  int v994; // [rsp+D0h] [rbp-288h]
  int v995; // [rsp+D8h] [rbp-280h]
  int v996; // [rsp+D8h] [rbp-280h]
  int v997; // [rsp+D8h] [rbp-280h]
  int v998; // [rsp+D8h] [rbp-280h]
  int v999; // [rsp+D8h] [rbp-280h]
  int v1000; // [rsp+D8h] [rbp-280h]
  int v1001; // [rsp+D8h] [rbp-280h]
  int v1002; // [rsp+D8h] [rbp-280h]
  unsigned int v1003; // [rsp+E4h] [rbp-274h]
  unsigned int v1004; // [rsp+E4h] [rbp-274h]
  unsigned int v1005; // [rsp+E4h] [rbp-274h]
  unsigned int v1006; // [rsp+E4h] [rbp-274h]
  unsigned int v1007; // [rsp+E8h] [rbp-270h]
  void **v1008; // [rsp+F0h] [rbp-268h]
  unsigned int v1009; // [rsp+F8h] [rbp-260h]
  unsigned int v1010; // [rsp+F8h] [rbp-260h]
  char *v1011; // [rsp+F8h] [rbp-260h]
  __int64 v1012; // [rsp+108h] [rbp-250h]
  void **v1013; // [rsp+110h] [rbp-248h]
  unsigned int v1014; // [rsp+110h] [rbp-248h]
  unsigned int v1015; // [rsp+118h] [rbp-240h]
  unsigned int v1016; // [rsp+118h] [rbp-240h]
  int v1017; // [rsp+11Ch] [rbp-23Ch]
  int v1018; // [rsp+11Ch] [rbp-23Ch]
  unsigned int v1019; // [rsp+11Ch] [rbp-23Ch]
  int v1020; // [rsp+11Ch] [rbp-23Ch]
  void **v1021; // [rsp+120h] [rbp-238h]
  int v1022; // [rsp+128h] [rbp-230h]
  int v1023; // [rsp+128h] [rbp-230h]
  void **v1024; // [rsp+130h] [rbp-228h]
  void **v1026; // [rsp+140h] [rbp-218h]
  _OWORD *v1027; // [rsp+148h] [rbp-210h]
  __int128 *v1030; // [rsp+188h] [rbp-1D0h]
  __int64 v1032; // [rsp+1A8h] [rbp-1B0h]
  unsigned int v1033; // [rsp+1B8h] [rbp-1A0h]
  void *v1034[2]; // [rsp+1C0h] [rbp-198h] BYREF
  _BYTE v1035[16]; // [rsp+1D0h] [rbp-188h] BYREF
  __int128 v1036; // [rsp+1E0h] [rbp-178h] BYREF
  void *v1037; // [rsp+1F0h] [rbp-168h]
  __int128 *v1038; // [rsp+1F8h] [rbp-160h]
  __int128 v1039; // [rsp+200h] [rbp-158h] BYREF
  void *v1040[2]; // [rsp+210h] [rbp-148h] BYREF
  char v1041; // [rsp+220h] [rbp-138h] BYREF
  void *v1042[2]; // [rsp+230h] [rbp-128h] BYREF
  char v1043; // [rsp+240h] [rbp-118h] BYREF
  _BYTE v1044[16]; // [rsp+250h] [rbp-108h] BYREF
  void *ptr[2]; // [rsp+260h] [rbp-F8h] BYREF
  void *v1046; // [rsp+270h] [rbp-E8h] BYREF
  __int64 v1047; // [rsp+278h] [rbp-E0h]
  int v1048; // [rsp+280h] [rbp-D8h] BYREF
  int v1049; // [rsp+284h] [rbp-D4h]
  int v1050; // [rsp+288h] [rbp-D0h]
  int v1051; // [rsp+28Ch] [rbp-CCh]
  int v1052; // [rsp+290h] [rbp-C8h]
  int v1053; // [rsp+294h] [rbp-C4h]
  int v1054; // [rsp+298h] [rbp-C0h]
  int v1055; // [rsp+29Ch] [rbp-BCh]
  int v1056; // [rsp+2A0h] [rbp-B8h]
  int v1057; // [rsp+2A4h] [rbp-B4h]
  int v1058; // [rsp+2A8h] [rbp-B0h]
  int v1059; // [rsp+2ACh] [rbp-ACh]
  void *v1060; // [rsp+2B8h] [rbp-A0h] BYREF
  void *v1061[2]; // [rsp+2C0h] [rbp-98h] BYREF
  _QWORD v1062[17]; // [rsp+2D0h] [rbp-88h] BYREF

  v1062[10] = __readfsqword(0x28u);
  v1032 = sub_56CE9EA();
  v1026 = a1 + 2;
  for ( LODWORD(v4) = -997800486; ; LODWORD(v4) = 2111984431 )
  {
    while ( 1 )
    {
LABEL_2:
      while ( (int)v4 <= (int)&unk_1039CDD )
      {
        if ( (int)v4 <= -390622149 )
        {
          if ( (_DWORD)v4 == -1469387901 )
          {
            LODWORD(v4) = 2111984431;
          }
          else if ( (_DWORD)v4 == -997800486 )
          {
            v4 = &unk_1039CDE;
            if ( !*(_BYTE *)(v1032 + 1) )
              LODWORD(v4) = 127093981;
          }
        }
        else
        {
          switch ( (_DWORD)v4 )
          {
            case 0xE8B7943C:
              v1027 = v1044;
              LODWORD(v4) = -348825421;
              continue;
            case 0xEB3558B3:
              *v1027 = 0;
              v1021 = ptr;
              *(_OWORD *)ptr = 0;
              v1024 = v1061;
              v1062[0] = 0;
              *(_OWORD *)v1061 = xmmword_9EA8F0;
              v1012 = *a3;
              v12 = *((_DWORD *)a3 + 2);
              v979 = v1062;
              v969 = v1062;
              v976 = 0;
              v1014 = v12;
              v1017 = (unsigned __int64)v12 >> 29;
              v13 = 8 * v12;
              v1022 = 8 * v12;
              for ( i = -544619405; ; i = 848251583 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( i <= 848251582 )
                    {
                      if ( i <= -544619406 )
                      {
                        if ( i == -2109407181 )
                        {
                          i = 1843554541;
                          LODWORD(v1008) = 0;
                          v1007 = v1033;
                        }
                        else
                        {
                          i = 1843554541;
                          v1007 = 0;
                          LODWORD(v1008) = (_DWORD)v989;
                        }
                      }
                      else if ( i == -544619405 )
                      {
                        v1033 = 0;
                        i = -165828501;
                      }
                      else
                      {
                        LODWORD(v1062[0]) = v1022;
                        i = 1066382172;
                      }
                    }
                    if ( i > 1114565259 )
                      break;
                    if ( i == 848251583 )
                    {
                      LODWORD(v989) = v13;
                      i = -785424894;
                      if ( v13 + 63 < v1014 )
                        i = 1916821574;
                    }
                    else
                    {
                      HIDWORD(v1062[0]) += v1017;
                      v973 = 64 - v1033;
                      i = 1114565260;
                      if ( 64 - v1033 > v1014 )
                        i = -2109407181;
                    }
                  }
                  if ( i != 1114565260 )
                    break;
                  for ( j = 0; ; j = (_DWORD)v968 + 1 )
                  {
                    for ( k = -1785266232; ; k = -1827872406 )
                    {
                      while ( k <= -1207850492 )
                      {
                        if ( k == -1827872406 )
                        {
                          *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v1033) = *((_BYTE *)v1046 + v1012);
                          k = 976403079;
                        }
                        else
                        {
                          LODWORD(v968) = j;
                          k = -554264179;
                          if ( j < v973 )
                            k = -1207850491;
                        }
                      }
                      if ( k != -1207850491 )
                        break;
                      v1046 = (void *)(int)v968;
                    }
                    if ( k == -554264179 )
                      break;
                  }
                  v975 = v1061;
                  v26 = (int)v1061[0];
                  v27 = HIDWORD(v1061[0]);
                  v28 = (int)v1061[1];
                  v29 = HIDWORD(v1061[1]);
                  v30 = 0;
                  v31 = 0;
LABEL_126:
                  for ( m = 496118048; ; m = -673330124 )
                  {
                    while ( m > -942669484 )
                    {
                      if ( m == -942669483 )
                      {
                        LODWORD(v967) = *((unsigned __int8 *)&v1062[1] + (unsigned int)v1060)
                                      | (*((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v1060 + 1)) << 8);
                        LODWORD(v966) = (_DWORD)v1060 + 2;
                        m = -2007397661;
                      }
                      else
                      {
                        if ( m == -673330124 )
                        {
                          v33 = *((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v1060 + 3)) << 24;
                          *((_DWORD *)&v1046 + (unsigned int)v968) = v33 & (unsigned int)v967
                                                                   | ((unsigned int)v967 | ((unsigned __int8)v974 << 16))
                                                                   ^ v33;
                          v31 = (_DWORD)v968 + 1;
                          v30 = (_DWORD)v1060 + 4;
                          goto LABEL_126;
                        }
                        LODWORD(v1060) = v30;
                        LODWORD(v968) = v31;
                        m = -1614485789;
                        if ( v30 < 0x40 )
                          m = -942669483;
                      }
                    }
                    if ( m != -2007397661 )
                      break;
                    LOBYTE(v974) = *((_BYTE *)&v1062[1] + (unsigned int)v966);
                  }
                  v34 = v27 + __ROL4__((v29 & ~v27) + v26 + (v27 & v28) + (_DWORD)v1046 - 680876936, 7);
                  v35 = v34 + __ROL4__((v27 & v34) + HIDWORD(v1046) + v29 + (v28 & ~v34) - 389564586, 12);
                  v995 = v29;
                  v36 = v35 + __ROL4__((v34 & v35) + v1047 + v28 + (v27 & ~v35) + 606105819, 17);
                  v37 = v36 + __ROL4__((v35 & v36) + HIDWORD(v1047) + v27 + (v34 & ~v36) - 1044525330, 22);
                  v38 = v37 + __ROL4__((v36 & v37) + (v35 & ~v37) + v1048 + v34 - 176418897, 7);
                  LODWORD(v985) = v1049;
                  v39 = v38 + __ROL4__((v37 & v38) + (v36 & ~v38) + v1049 + v35 + 1200080426, 12);
                  v40 = v39 + __ROL4__((v37 & ~v39) + v1050 + v36 + (v38 & v39) - 1473231341, 17);
                  v991 = v26;
                  v41 = v40 + __ROL4__((v39 & v40) + (v38 & ~v40) + v1051 + v37 - 45705983, 22);
                  v42 = v41 + __ROL4__((v39 & ~v41) + v1052 + v38 + (v40 & v41) + 1770035416, 7);
                  v43 = v42 + __ROL4__((v41 & v42) + (v40 & ~v42) + v1053 + v39 - 1958414417, 12);
                  v44 = v43 + __ROL4__((v42 & v43) + (v41 & ~v43) + v1054 + v40 - 42063, 17);
                  v45 = v44 + __ROL4__((v43 & v44) + (v42 & ~v44) + v1055 + v41 - 1990404162, 22);
                  v46 = v45 + __ROL4__((v44 & v45) + (v43 & ~v45) + v1056 + v42 + 1804603682, 7);
                  v47 = v46 + __ROL4__((v44 & ~v46) + v1057 + v43 + (v45 & v46) - 40341101, 12);
                  v48 = v47 + __ROL4__((~v47 & v45) + v1058 + v44 + (v46 & v47) - 1502002290, 17);
                  v990 = v28;
                  v49 = v48 + __ROL4__((v47 & v48) + (~v48 & v46) + v1059 + v45 + 1236535329, 22);
                  v50 = v49 + __ROL4__((v47 & v49) + HIDWORD(v1046) + v46 + (v48 & ~v47) - 165796510, 5);
                  v51 = v50 + __ROL4__((v48 & v50) + (v49 & ~v48) + v1050 + v47 - 1069501632, 9);
                  v52 = v51 + __ROL4__((v49 & v51) + (v50 & ~v49) + v1055 + v48 + 643717713, 14);
                  v53 = v52 + __ROL4__((v50 & v52) + (v51 & ~v50) + (_DWORD)v1046 + v49 - 373897302, 20);
                  v54 = v53 + __ROL4__((v51 & v53) + (v52 & ~v51) + v1049 + v50 - 701558691, 5);
                  v55 = v54 + __ROL4__((v52 & v54) + (v53 & ~v52) + v1054 + v51 + 38016083, 9);
                  v56 = v55 + __ROL4__((v53 & v55) + (v54 & ~v53) + v1059 + v52 - 660478335, 14);
                  v57 = v56 + __ROL4__((v54 & v56) + (v55 & ~v54) + v1048 + v53 - 405537848, 20);
                  v58 = v57 + __ROL4__((v55 & v57) + (v56 & ~v55) + v1053 + v54 + 568446438, 5);
                  v59 = v58 + __ROL4__((v56 & v58) + (v57 & ~v56) + v1058 + v55 - 1019803690, 9);
                  v60 = v59 + __ROL4__((v57 & v59) + (v58 & ~v57) + HIDWORD(v1047) + v56 - 187363961, 14);
                  v61 = v60 + __ROL4__((v58 & v60) + (v59 & ~v58) + v1052 + v57 + 1163531501, 20);
                  v62 = v61 + __ROL4__((v59 & v61) + (v60 & ~v59) + v1057 + v58 - 1444681467, 5);
                  v63 = v62 + __ROL4__((v60 & v62) + (v61 & ~v60) + v1047 + v59 - 51403784, 9);
                  v64 = v63 + __ROL4__((v61 & v63) + (v62 & ~v61) + v1051 + v60 + 1735328473, 14);
                  v65 = v64 + __ROL4__((v63 & ~v62) + v1056 + v61 + (v62 & v64) - 1926607734, 20);
                  v66 = v65 + __ROL4__((v63 ^ v64 ^ v65) + v1049 + v62 - 378558, 4);
                  v67 = v66 + __ROL4__(v1052 + v63 + (v66 ^ v64 ^ v65) - 2022574463, 11);
                  v68 = v67 + __ROL4__(v1055 + v64 + (v65 ^ v66 ^ v67) + 1839030562, 16);
                  v69 = v68 + __ROL4__(v1058 + v65 + (v68 ^ v66 ^ v67) - 35309556, 23);
                  v70 = v69 + __ROL4__((v67 ^ v68 ^ v69) + HIDWORD(v1046) + v66 - 1530992060, 4);
                  v71 = v70 + __ROL4__((v70 ^ v68 ^ v69) + v1048 + v67 + 1272893353, 11);
                  v72 = v71 + __ROL4__(v1051 + v68 + (v69 ^ v70 ^ v71) - 155497632, 16);
                  v73 = v72 + __ROL4__((v72 ^ v70 ^ v71) + v1054 + v69 - 1094730640, 23);
                  v74 = v73 + __ROL4__((v73 ^ v71 ^ v72) + v1057 + v70 + 681279174, 4);
                  v75 = v74 + __ROL4__((_DWORD)v1046 + v71 + (v74 ^ v72 ^ v73) - 358537222, 11);
                  v76 = v75 + __ROL4__((v75 ^ v73 ^ v74) + HIDWORD(v1047) + v72 - 722521979, 16);
                  v77 = v76 + __ROL4__((v76 ^ v74 ^ v75) + v1050 + v73 + 76029189, 23);
                  v78 = v77 + __ROL4__(v1053 + v74 + (v77 ^ v75 ^ v76) - 640364487, 4);
                  v79 = v78 + __ROL4__((v78 ^ v76 ^ v77) + v1056 + v75 - 421815835, 11);
                  v80 = v79 + __ROL4__((v79 ^ v77 ^ v78) + v1059 + v76 + 530742520, 16);
                  v81 = v80 + __ROL4__((v80 ^ v78 ^ v79) + v1047 + v77 - 995338651, 23);
                  v82 = v81 + __ROL4__((v80 ^ (v81 | ~v79)) + (_DWORD)v1046 + v78 - 198630844, 6);
                  v83 = v82 + __ROL4__((v81 ^ (v82 | ~v80)) + v1051 + v79 + 1126891415, 10);
                  v84 = v83 + __ROL4__((v82 ^ (v83 | ~v81)) + v1058 + v80 - 1416354905, 15);
                  v85 = v84 + __ROL4__((v83 ^ (v84 | ~v82)) + v1049 + v81 - 57434055, 21);
                  v86 = v85 + __ROL4__(v1056 + v82 + (v84 ^ (v85 | ~v83)) + 1700485571, 6);
                  v87 = v86 + __ROL4__(HIDWORD(v1047) + v83 + (v85 ^ (v86 | ~v84)) - 1894986606, 10);
                  v88 = v87 + __ROL4__((v86 ^ (~(v87 ^ v85) | v87 & ~v85)) + v1054 + v84 - 1051523, 15);
                  v89 = v88 + __ROL4__((v87 ^ (v88 | ~v86)) + HIDWORD(v1046) + v85 - 2054922799, 21);
                  v90 = v89 + __ROL4__((v88 ^ (v89 | ~v87)) + v1052 + v86 + 1873313359, 6);
                  v91 = v90 + __ROL4__((v89 ^ (v90 | ~v88)) + v1059 + v87 - 30611744, 10);
                  v92 = v91 + __ROL4__((v90 ^ (~(v91 ^ v89) | v91 & ~v89)) + v1050 + v88 - 1560198380, 15);
                  v93 = v92 + __ROL4__((v91 ^ (~(v90 ^ v92) | v92 & ~v90)) + v1057 + v89 + 1309151649, 21);
                  v94 = v93 + __ROL4__(v1048 + v90 + (v92 ^ (v93 | ~v91)) - 145523070, 6);
                  v95 = v94 + __ROL4__((v93 ^ (~(v94 ^ v92) | v94 & ~v92)) + v1055 + v91 - 1120210379, 10);
                  v96 = v95 + __ROL4__(v1047 + v92 + (v94 ^ (v95 | ~v93)) + 718787259, 15);
                  LODWORD(v1061[0]) = v991 + v94;
                  HIDWORD(v1061[0]) = __ROL4__((v95 ^ (v96 | ~v94)) + v1053 + v93 - 343485551, 21) + v96 + v27;
                  LODWORD(v1061[1]) = v990 + v96;
                  HIDWORD(v1061[1]) = v995 + v95;
                  v97 = 0;
LABEL_138:
                  v98 = 976919488;
                  while ( 1 )
                  {
                    while ( v98 <= -587301062 )
                    {
                      if ( v98 == -1016511951 )
                      {
                        v97 = (unsigned int)v1060;
                        goto LABEL_138;
                      }
                      *((_BYTE *)&v1046 + (int)v968) = 0;
                      v98 = -455638576;
                    }
                    if ( v98 == -587301061 )
                      break;
                    if ( v98 == -455638576 )
                    {
                      LODWORD(v1060) = (_DWORD)v968 + 1;
                      v98 = -1016511951;
                    }
                    else
                    {
                      LODWORD(v968) = v97;
                      v98 = -587301061;
                      if ( v97 < 0x40 )
                        v98 = -588599311;
                    }
                  }
                  i = 848251583;
                  v13 = v973;
                }
                if ( i != 1916821574 )
                  break;
                v15 = v1012 + (unsigned int)v989;
                v16 = *(_DWORD *)v975;
                v17 = *((_DWORD *)v975 + 1);
                v18 = *((_DWORD *)v975 + 2);
                v19 = *((_DWORD *)v975 + 3);
                v20 = 0;
                v21 = 0;
LABEL_90:
                for ( n = 496118048; ; n = -673330124 )
                {
                  while ( n > -942669484 )
                  {
                    if ( n == -942669483 )
                    {
                      LODWORD(v967) = *(unsigned __int8 *)(v15 + (unsigned int)v1060)
                                    | (*(unsigned __int8 *)(v15 + (unsigned int)((_DWORD)v1060 + 1)) << 8);
                      LODWORD(v966) = (_DWORD)v1060 + 2;
                      n = -2007397661;
                    }
                    else
                    {
                      if ( n == -673330124 )
                      {
                        v23 = *(unsigned __int8 *)(v15 + (unsigned int)((_DWORD)v1060 + 3)) << 24;
                        *((_DWORD *)&v1046 + (unsigned int)v968) = v23 & (unsigned int)v967
                                                                 | ((unsigned int)v967 | ((unsigned __int8)v974 << 16))
                                                                 ^ v23;
                        v21 = (_DWORD)v968 + 1;
                        v20 = (_DWORD)v1060 + 4;
                        goto LABEL_90;
                      }
                      LODWORD(v1060) = v20;
                      LODWORD(v968) = v21;
                      n = -1614485789;
                      if ( v20 < 0x40 )
                        n = -942669483;
                    }
                  }
                  if ( n != -2007397661 )
                    break;
                  LOBYTE(v974) = *(_BYTE *)(v15 + (unsigned int)v966);
                }
                v99 = v17 + __ROL4__((v19 & ~v17) + v16 + (v17 & v18) + (_DWORD)v1046 - 680876936, 7);
                v100 = v99 + __ROL4__((v17 & v99) + HIDWORD(v1046) + v19 + (v18 & ~v99) - 389564586, 12);
                v101 = v100 + __ROL4__((v99 & v100) + v18 + v1047 + (v17 & ~v100) + 606105819, 17);
                v102 = v101 + __ROL4__((v100 & v101) + v17 + HIDWORD(v1047) + (v99 & ~v101) - 1044525330, 22);
                v103 = v102 + __ROL4__((v101 & v102) + (v100 & ~v102) + v1048 + v99 - 176418897, 7);
                v104 = v103 + __ROL4__((v102 & v103) + (v101 & ~v103) + v1049 + v100 + 1200080426, 12);
                v105 = v104 + __ROL4__((v103 & v104) + (v102 & ~v104) + v1050 + v101 - 1473231341, 17);
                v106 = v105 + __ROL4__((v104 & v105) + (v103 & ~v105) + v1051 + v102 - 45705983, 22);
                v107 = v106 + __ROL4__((v105 & v106) + (v104 & ~v106) + v1052 + v103 + 1770035416, 7);
                v108 = v107 + __ROL4__((v106 & v107) + (v105 & ~v107) + v1053 + v104 - 1958414417, 12);
                LODWORD(v985) = v19;
                v109 = v108 + __ROL4__((v107 & v108) + (v106 & ~v108) + v1054 + v105 - 42063, 17);
                v110 = v109 + __ROL4__((v108 & v109) + (v107 & ~v109) + v1055 + v106 - 1990404162, 22);
                v111 = v110 + __ROL4__((v108 & ~v110) + v1056 + v107 + (v109 & v110) + 1804603682, 7);
                v996 = v16;
                v112 = v111 + __ROL4__((v110 & v111) + (v109 & ~v111) + v1057 + v108 - 40341101, 12);
                v113 = v112 + __ROL4__((~v112 & v110) + v1058 + v109 + (v111 & v112) - 1502002290, 17);
                v114 = v111 + HIDWORD(v1046);
                v115 = v113 + __ROL4__((~v113 & v111) + v1059 + v110 + (v112 & v113) + 1236535329, 22);
                v116 = v115 + __ROL4__((v112 & v115) + v114 + (v113 & ~v112) - 165796510, 5);
                v117 = v116 + __ROL4__((v113 & v116) + (v115 & ~v113) + v1050 + v112 - 1069501632, 9);
                v118 = v117 + __ROL4__((v115 & v117) + (v116 & ~v115) + v1055 + v113 + 643717713, 14);
                v119 = v118 + __ROL4__((v116 & v118) + (v117 & ~v116) + (_DWORD)v1046 + v115 - 373897302, 20);
                v120 = v119 + __ROL4__((v117 & v119) + (v118 & ~v117) + v1049 + v116 - 701558691, 5);
                v121 = v120 + __ROL4__((v119 & ~v118) + v1054 + v117 + (v118 & v120) + 38016083, 9);
                v122 = v121 + __ROL4__((v119 & v121) + (v120 & ~v119) + v1059 + v118 - 660478335, 14);
                v123 = v122 + __ROL4__((v120 & v122) + (v121 & ~v120) + v1048 + v119 - 405537848, 20);
                v124 = v123 + __ROL4__((v121 & v123) + (v122 & ~v121) + v1053 + v120 + 568446438, 5);
                v125 = v124 + __ROL4__((v122 & v124) + (v123 & ~v122) + v1058 + v121 - 1019803690, 9);
                v126 = v125 + __ROL4__((v123 & v125) + (v124 & ~v123) + HIDWORD(v1047) + v122 - 187363961, 14);
                v127 = v126 + __ROL4__((v125 & ~v124) + v1052 + v123 + (v124 & v126) + 1163531501, 20);
                v128 = v127 + __ROL4__((v126 & ~v125) + v1057 + v124 + (v125 & v127) - 1444681467, 5);
                v129 = v128 + __ROL4__((v126 & v128) + (v127 & ~v126) + v1047 + v125 - 51403784, 9);
                v130 = v129 + __ROL4__((v127 & v129) + (v128 & ~v127) + v1051 + v126 + 1735328473, 14);
                v131 = v130 + __ROL4__((v129 & ~v128) + v1056 + v127 + (v128 & v130) - 1926607734, 20);
                v132 = v131 + __ROL4__(v1049 + v128 + (v129 ^ v130 ^ v131) - 378558, 4);
                v133 = v132 + __ROL4__(v1052 + v129 + (v132 ^ v130 ^ v131) - 2022574463, 11);
                v134 = v133 + __ROL4__((v131 ^ v132 ^ v133) + v1055 + v130 + 1839030562, 16);
                v135 = v134 + __ROL4__((v134 ^ v132 ^ v133) + v1058 + v131 - 35309556, 23);
                v136 = v135 + __ROL4__(HIDWORD(v1046) + v132 + (v133 ^ v134 ^ v135) - 1530992060, 4);
                v137 = v136 + __ROL4__((v136 ^ v134 ^ v135) + v1048 + v133 + 1272893353, 11);
                v138 = v137 + __ROL4__(v1051 + v134 + (v135 ^ v136 ^ v137) - 155497632, 16);
                v139 = v138 + __ROL4__((v138 ^ v136 ^ v137) + v1054 + v135 - 1094730640, 23);
                v140 = v139 + __ROL4__(v1057 + v136 + (v139 ^ v137 ^ v138) + 681279174, 4);
                v141 = v140 + __ROL4__((_DWORD)v1046 + v137 + (v140 ^ v138 ^ v139) - 358537222, 11);
                v142 = v141 + __ROL4__((v141 ^ v139 ^ v140) + HIDWORD(v1047) + v138 - 722521979, 16);
                v143 = v142 + __ROL4__(v1050 + v139 + (v142 ^ v140 ^ v141) + 76029189, 23);
                v144 = v143 + __ROL4__((v143 ^ v141 ^ v142) + v1053 + v140 - 640364487, 4);
                v145 = v144 + __ROL4__((v144 ^ v142 ^ v143) + v1056 + v141 - 421815835, 11);
                v146 = v145 + __ROL4__((v145 ^ v143 ^ v144) + v1059 + v142 + 530742520, 16);
                v147 = v146 + __ROL4__((v146 ^ v144 ^ v145) + v1047 + v143 - 995338651, 23);
                v148 = v147 + __ROL4__((v146 ^ (v147 | ~v145)) + (_DWORD)v1046 + v144 - 198630844, 6);
                v149 = v148 + __ROL4__((v147 ^ (v148 | ~v146)) + v1051 + v145 + 1126891415, 10);
                v150 = v149 + __ROL4__((v148 ^ (v149 | ~v147)) + v1058 + v146 - 1416354905, 15);
                v151 = v150 + __ROL4__(v1049 + v147 + (v149 ^ (v150 | ~v148)) - 57434055, 21);
                v152 = v151 + __ROL4__((v150 ^ (v151 | ~v149)) + v1056 + v148 + 1700485571, 6);
                v153 = v152 + __ROL4__((v151 ^ (v152 | ~v150)) + HIDWORD(v1047) + v149 - 1894986606, 10);
                v154 = v153 + __ROL4__((v152 ^ (~(v153 ^ v151) | v153 & ~v151)) + v1054 + v150 - 1051523, 15);
                v155 = v154 + __ROL4__((v153 ^ (v154 | ~v152)) + HIDWORD(v1046) + v151 - 2054922799, 21);
                v156 = v155 + __ROL4__((v154 ^ (v155 | ~v153)) + v1052 + v152 + 1873313359, 6);
                v157 = v156 + __ROL4__((v155 ^ (v156 | ~v154)) + v1059 + v153 - 30611744, 10);
                v158 = v157 + __ROL4__((v156 ^ (~(v157 ^ v155) | v157 & ~v155)) + v1050 + v154 - 1560198380, 15);
                v159 = v158 + __ROL4__((v157 ^ (~(v156 ^ v158) | v158 & ~v156)) + v1057 + v155 + 1309151649, 21);
                v160 = v159 + __ROL4__(v1048 + v156 + (v158 ^ (v159 | ~v157)) - 145523070, 6);
                v161 = v160 + __ROL4__((v159 ^ (~(v160 ^ v158) | v160 & ~v158)) + v1055 + v157 - 1120210379, 10);
                v162 = v161 + __ROL4__(v1047 + v158 + (v160 ^ (v161 | ~v159)) + 718787259, 15);
                v163 = (v161 ^ (v162 | ~v160)) + v1053 + v159 - 343485551;
                *(_DWORD *)v975 = v996 + v160;
                *((_DWORD *)v975 + 1) = __ROL4__(v163, 21) + v162 + v17;
                *((_DWORD *)v975 + 2) = v18 + v162;
                *((_DWORD *)v975 + 3) = (_DWORD)v985 + v161;
                v164 = 0;
LABEL_150:
                v165 = 976919488;
                while ( 1 )
                {
                  while ( v165 <= -587301062 )
                  {
                    if ( v165 == -1016511951 )
                    {
                      v164 = (unsigned int)v1060;
                      goto LABEL_150;
                    }
                    *((_BYTE *)&v1046 + (int)v968) = 0;
                    v165 = -455638576;
                  }
                  if ( v165 == -587301061 )
                    break;
                  if ( v165 == -455638576 )
                  {
                    LODWORD(v1060) = (_DWORD)v968 + 1;
                    v165 = -1016511951;
                  }
                  else
                  {
                    LODWORD(v968) = v164;
                    v165 = -587301061;
                    if ( v164 < 0x40 )
                      v165 = -588599311;
                  }
                }
                v13 = (_DWORD)v989 + 64;
              }
              LODWORD(v1013) = v1014 - (_DWORD)v1008;
              for ( ii = 0; ; ii = (_DWORD)v968 + 1 )
              {
                for ( jj = -1785266232; ; jj = -1827872406 )
                {
                  while ( jj <= -1207850492 )
                  {
                    if ( jj == -1827872406 )
                    {
                      *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v1007) = *((_BYTE *)v1046 + (unsigned int)v1008 + v1012);
                      jj = 976403079;
                    }
                    else
                    {
                      LODWORD(v968) = ii;
                      jj = -554264179;
                      if ( ii < (unsigned int)v1013 )
                        jj = -1207850491;
                    }
                  }
                  if ( jj != -1207850491 )
                    break;
                  v1046 = (void *)(int)v968;
                }
                if ( jj == -554264179 )
                  break;
              }
              v968 = (unsigned int *)ptr;
              v168 = 0;
              v169 = 0;
LABEL_175:
              for ( kk = -1717192363; ; kk = -2031488434 )
              {
                while ( 1 )
                {
                  while ( kk <= -736119120 )
                  {
                    if ( kk == -2031488434 )
                    {
                      *((_BYTE *)&v1061[-1] + (unsigned int)v979) = (_BYTE)v966;
                      v169 = (_DWORD)v975 + 1;
                      v168 = (_DWORD)v969 + 4;
                      goto LABEL_175;
                    }
                    LODWORD(v969) = v168;
                    LODWORD(v975) = v169;
                    kk = 494299060;
                    if ( v168 < 8 )
                      kk = -736119119;
                  }
                  if ( kk != -736119119 )
                    break;
                  v1046 = (char *)v1062 + 4 * (unsigned int)v975;
                  *((_BYTE *)&v1061[-1] + (unsigned int)v969) = *(_BYTE *)v1046;
                  *((_BYTE *)&v1061[-1] + (unsigned int)((_DWORD)v969 + 1)) = *((_BYTE *)v1046 + 1);
                  *((_BYTE *)&v1061[-1] + (unsigned int)((_DWORD)v969 + 2)) = *((_BYTE *)v1046 + 2);
                  kk = 1223234202;
                }
                if ( kk == 494299060 )
                  break;
                LOBYTE(v966) = *((_BYTE *)v1046 + 3);
                LODWORD(v979) = (_DWORD)v969 + 3;
              }
              v171 = ((((LODWORD(v1062[0]) >> 3) & 0x3F) >= 0x38) << 6) - ((LODWORD(v1062[0]) >> 3) & 0x3F);
              v1003 = v1062[0];
              v1009 = v171 + 56;
              v1015 = (unsigned int)(v171 + 56) >> 29;
              v172 = 8 * v171 + 448;
              v1018 = v172;
              for ( mm = -544619405; ; mm = 848251583 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( mm <= 848251582 )
                    {
                      if ( mm <= -544619406 )
                      {
                        if ( mm == -2109407181 )
                        {
                          mm = 1843554541;
                          LODWORD(v1013) = 0;
                          LODWORD(v1012) = v974;
                        }
                        else
                        {
                          mm = 1843554541;
                          LODWORD(v1012) = 0;
                          LODWORD(v1013) = v1033;
                        }
                      }
                      else if ( mm == -544619405 )
                      {
                        v974 = (v1003 >> 3) & 0x3F;
                        mm = -165828501;
                      }
                      else if ( mm == -316297161 )
                      {
                        ++HIDWORD(v1062[0]);
                        mm = 1066382172;
                      }
                      else
                      {
                        LODWORD(v1062[0]) = v1018 + v1003;
                        mm = 1066382172;
                        if ( __CFADD__(v1018, v1003) )
                          mm = -316297161;
                      }
                    }
                    if ( mm > 1114565259 )
                      break;
                    if ( mm == 848251583 )
                    {
                      v1033 = v172;
                      mm = -785424894;
                      if ( v172 + 63 < v1009 )
                        mm = 1916821574;
                    }
                    else
                    {
                      HIDWORD(v1062[0]) += v1015;
                      v976 = 64 - v974;
                      mm = 1114565260;
                      if ( 64 - v974 > v1009 )
                        mm = -2109407181;
                    }
                  }
                  if ( mm != 1114565260 )
                    break;
                  for ( nn = 0; ; nn = (_DWORD)v966 + 1 )
                  {
                    for ( i1 = -1785266232; ; i1 = -1827872406 )
                    {
                      while ( i1 <= -1207850492 )
                      {
                        if ( i1 == -1827872406 )
                        {
                          *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v974) = *((_BYTE *)&unk_D407C0 + (_QWORD)v1046);
                          i1 = 976403079;
                        }
                        else
                        {
                          LODWORD(v966) = nn;
                          i1 = -554264179;
                          if ( nn < v976 )
                            i1 = -1207850491;
                        }
                      }
                      if ( i1 != -1207850491 )
                        break;
                      v1046 = (void *)(int)v966;
                    }
                    if ( i1 == -554264179 )
                      break;
                  }
                  v975 = v1061;
                  v184 = (int)v1061[0];
                  v185 = HIDWORD(v1061[0]);
                  v186 = (unsigned int)v1061[1];
                  v187 = HIDWORD(v1061[1]);
                  v188 = 0;
                  v189 = 0;
LABEL_235:
                  for ( i2 = 496118048; ; i2 = -673330124 )
                  {
                    while ( i2 > -942669484 )
                    {
                      if ( i2 == -942669483 )
                      {
                        v973 = *((unsigned __int8 *)&v1062[1] + (unsigned int)v967)
                             | (*((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 1)) << 8);
                        LODWORD(v989) = (_DWORD)v967 + 2;
                        i2 = -2007397661;
                      }
                      else
                      {
                        if ( i2 == -673330124 )
                        {
                          v191 = *((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 3)) << 24;
                          *((_DWORD *)&v1046 + (unsigned int)v966) = v191 & v973 | (v973 | (v965 << 16)) ^ v191;
                          v189 = (_DWORD)v966 + 1;
                          v188 = (_DWORD)v967 + 4;
                          goto LABEL_235;
                        }
                        LODWORD(v967) = v188;
                        LODWORD(v966) = v189;
                        i2 = -1614485789;
                        if ( v188 < 0x40 )
                          i2 = -942669483;
                      }
                    }
                    if ( i2 != -2007397661 )
                      break;
                    v965 = *((_BYTE *)&v1062[1] + (unsigned int)v989);
                  }
                  v192 = v185 + __ROL4__((_DWORD)v1046 + (v187 & ~v185) + v184 + (v185 & v186) - 680876936, 7);
                  v193 = v192 + __ROL4__(HIDWORD(v1046) + v187 + (v186 & ~v192) + (v185 & v192) - 389564586, 12);
                  LODWORD(v1008) = v187;
                  v194 = v193 + __ROL4__((v192 & v193) + v1047 + v186 + (v185 & ~v193) + 606105819, 17);
                  v195 = v194 + __ROL4__((v193 & v194) + v185 + HIDWORD(v1047) + (v192 & ~v194) - 1044525330, 22);
                  v196 = v195 + __ROL4__((v194 & v195) + (v193 & ~v195) + v1048 + v192 - 176418897, 7);
                  v197 = v196 + __ROL4__((v195 & v196) + (v194 & ~v196) + v1049 + v193 + 1200080426, 12);
                  v198 = v197 + __ROL4__((v196 & v197) + (v195 & ~v197) + v1050 + v194 - 1473231341, 17);
                  v1007 = v186;
                  v199 = v198 + __ROL4__((v197 & v198) + (v196 & ~v198) + v1051 + v195 - 45705983, 22);
                  v200 = v199 + __ROL4__((v198 & v199) + (v197 & ~v199) + v1052 + v196 + 1770035416, 7);
                  v201 = v200 + __ROL4__((v199 & v200) + (v198 & ~v200) + v1053 + v197 - 1958414417, 12);
                  v202 = v201 + __ROL4__((v199 & ~v201) + v1054 + v198 + (v200 & v201) - 42063, 17);
                  v203 = v202 + __ROL4__((v201 & v202) + (v200 & ~v202) + v1055 + v199 - 1990404162, 22);
                  v204 = v203 + __ROL4__((v202 & v203) + (v201 & ~v203) + v1056 + v200 + 1804603682, 7);
                  LODWORD(v985) = v1057;
                  v205 = v204 + __ROL4__((v202 & ~v204) + v1057 + v201 + (v203 & v204) - 40341101, 12);
                  v206 = v205 + __ROL4__((v204 & v205) + (~v205 & v203) + v1058 + v202 - 1502002290, 17);
                  v207 = v206 + __ROL4__((~v206 & v204) + v1059 + v203 + (v205 & v206) + 1236535329, 22);
                  v208 = v207 + __ROL4__((v205 & v207) + v204 + HIDWORD(v1046) + (v206 & ~v205) - 165796510, 5);
                  v209 = v208 + __ROL4__((v206 & v208) + (v207 & ~v206) + v1050 + v205 - 1069501632, 9);
                  v210 = v209 + __ROL4__((v207 & v209) + (v208 & ~v207) + v1055 + v206 + 643717713, 14);
                  v211 = v210 + __ROL4__((v208 & v210) + (v209 & ~v208) + (_DWORD)v1046 + v207 - 373897302, 20);
                  v212 = v211 + __ROL4__((v210 & ~v209) + v1049 + v208 + (v209 & v211) - 701558691, 5);
                  v213 = v212 + __ROL4__((v210 & v212) + (v211 & ~v210) + v1054 + v209 + 38016083, 9);
                  v214 = v213 + __ROL4__((v211 & v213) + (v212 & ~v211) + v1059 + v210 - 660478335, 14);
                  v215 = v214 + __ROL4__((v212 & v214) + (v213 & ~v212) + v1048 + v211 - 405537848, 20);
                  v216 = v215 + __ROL4__((v213 & v215) + (v214 & ~v213) + v1053 + v212 + 568446438, 5);
                  v217 = v216 + __ROL4__((v214 & v216) + (v215 & ~v214) + v1058 + v213 - 1019803690, 9);
                  v218 = v217 + __ROL4__((v215 & v217) + (v216 & ~v215) + HIDWORD(v1047) + v214 - 187363961, 14);
                  v219 = v218 + __ROL4__((v216 & v218) + (v217 & ~v216) + v1052 + v215 + 1163531501, 20);
                  v220 = v219 + __ROL4__((v217 & v219) + (v218 & ~v217) + v1057 + v216 - 1444681467, 5);
                  v221 = v220 + __ROL4__((v218 & v220) + (v219 & ~v218) + v1047 + v217 - 51403784, 9);
                  v222 = v221 + __ROL4__((v219 & v221) + (v220 & ~v219) + v1051 + v218 + 1735328473, 14);
                  v223 = v222 + __ROL4__((v220 & v222) + (v221 & ~v220) + v1056 + v219 - 1926607734, 20);
                  v224 = v223 + __ROL4__(v1049 + v220 + (v221 ^ v222 ^ v223) - 378558, 4);
                  v225 = v224 + __ROL4__((v224 ^ v222 ^ v223) + v1052 + v221 - 2022574463, 11);
                  v226 = v225 + __ROL4__(v1055 + v222 + (v223 ^ v224 ^ v225) + 1839030562, 16);
                  v227 = v226 + __ROL4__((v226 ^ v224 ^ v225) + v1058 + v223 - 35309556, 23);
                  v228 = v227 + __ROL4__((v225 ^ v226 ^ v227) + HIDWORD(v1046) + v224 - 1530992060, 4);
                  v229 = v228 + __ROL4__((v228 ^ v226 ^ v227) + v1048 + v225 + 1272893353, 11);
                  v230 = v229 + __ROL4__((v227 ^ v228 ^ v229) + v1051 + v226 - 155497632, 16);
                  v231 = v230 + __ROL4__((v230 ^ v228 ^ v229) + v1054 + v227 - 1094730640, 23);
                  v232 = v231 + __ROL4__((v229 ^ v230 ^ v231) + v1057 + v228 + 681279174, 4);
                  v233 = v185;
                  v234 = v232 + __ROL4__((_DWORD)v1046 + v229 + (v232 ^ v230 ^ v231) - 358537222, 11);
                  v235 = v234 + __ROL4__((v234 ^ v231 ^ v232) + HIDWORD(v1047) + v230 - 722521979, 16);
                  v236 = v235 + __ROL4__((v235 ^ v232 ^ v234) + v1050 + v231 + 76029189, 23);
                  v237 = v236 + __ROL4__((v236 ^ v234 ^ v235) + v1053 + v232 - 640364487, 4);
                  v238 = v237 + __ROL4__(v1056 + v234 + (v237 ^ v235 ^ v236) - 421815835, 11);
                  v239 = v238 + __ROL4__((v238 ^ v236 ^ v237) + v1059 + v235 + 530742520, 16);
                  v240 = v239 + __ROL4__((v239 ^ v237 ^ v238) + v1047 + v236 - 995338651, 23);
                  v241 = v240 + __ROL4__((_DWORD)v1046 + v237 + (v239 ^ (v240 | ~v238)) - 198630844, 6);
                  v242 = v241 + __ROL4__((v240 ^ (v241 | ~v239)) + v1051 + v238 + 1126891415, 10);
                  v243 = v242 + __ROL4__((v241 ^ (v242 | ~v240)) + v1058 + v239 - 1416354905, 15);
                  v244 = v243 + __ROL4__((v242 ^ (v243 | ~v241)) + v1049 + v240 - 57434055, 21);
                  v245 = v244 + __ROL4__((v243 ^ (v244 | ~v242)) + v1056 + v241 + 1700485571, 6);
                  v246 = v245 + __ROL4__((v244 ^ (v245 | ~v243)) + HIDWORD(v1047) + v242 - 1894986606, 10);
                  v247 = v246 + __ROL4__((v245 ^ (~(v246 ^ v244) | v246 & ~v244)) + v1054 + v243 - 1051523, 15);
                  v248 = v247 + __ROL4__((v246 ^ (v247 | ~v245)) + HIDWORD(v1046) + v244 - 2054922799, 21);
                  v249 = v248 + __ROL4__((v247 ^ (v248 | ~v246)) + v1052 + v245 + 1873313359, 6);
                  v250 = v249 + __ROL4__(v1059 + v246 + (v248 ^ (v249 | ~v247)) - 30611744, 10);
                  v251 = v250 + __ROL4__((v249 ^ (~(v250 ^ v248) | v250 & ~v248)) + v1050 + v247 - 1560198380, 15);
                  v252 = v251 + __ROL4__((v250 ^ (~(v249 ^ v251) | v251 & ~v249)) + v1057 + v248 + 1309151649, 21);
                  v253 = v252 + __ROL4__(v1048 + v249 + (v251 ^ (v252 | ~v250)) - 145523070, 6);
                  v254 = v253 + __ROL4__((v252 ^ (~(v253 ^ v251) | v253 & ~v251)) + v1055 + v250 - 1120210379, 10);
                  v255 = v254 + __ROL4__(v1047 + v251 + (v253 ^ (v254 | ~v252)) + 718787259, 15);
                  LODWORD(v1061[0]) = v184 + v253;
                  HIDWORD(v1061[0]) = __ROL4__((v254 ^ (v255 | ~v253)) + v1053 + v252 - 343485551, 21) + v255 + v233;
                  LODWORD(v1061[1]) = v1007 + v255;
                  HIDWORD(v1061[1]) = (_DWORD)v1008 + v254;
                  v256 = 0;
LABEL_247:
                  v257 = 976919488;
                  while ( 1 )
                  {
                    while ( v257 <= -587301062 )
                    {
                      if ( v257 == -1016511951 )
                      {
                        v256 = (unsigned int)v967;
                        goto LABEL_247;
                      }
                      *((_BYTE *)&v1046 + (int)v966) = 0;
                      v257 = -455638576;
                    }
                    if ( v257 == -587301061 )
                      break;
                    if ( v257 == -455638576 )
                    {
                      LODWORD(v967) = (_DWORD)v966 + 1;
                      v257 = -1016511951;
                    }
                    else
                    {
                      LODWORD(v966) = v256;
                      v257 = -587301061;
                      if ( v256 < 0x40 )
                        v257 = -588599311;
                    }
                  }
                  mm = 848251583;
                  v172 = v976;
                }
                if ( mm != 1916821574 )
                  break;
                v174 = *(_DWORD *)v975;
                v175 = *((_DWORD *)v975 + 1);
                v176 = *((_DWORD *)v975 + 2);
                v177 = *((_DWORD *)v975 + 3);
                v178 = 0;
                v179 = 0;
LABEL_198:
                for ( i3 = 496118048; ; i3 = -673330124 )
                {
                  while ( i3 > -942669484 )
                  {
                    if ( i3 == -942669483 )
                    {
                      v973 = *((unsigned __int8 *)&unk_D407C0 + v1033 + (unsigned __int64)(unsigned int)v967)
                           | (*((unsigned __int8 *)&unk_D407C0
                              + v1033
                              + (unsigned __int64)(unsigned int)((_DWORD)v967 + 1)) << 8);
                      LODWORD(v989) = (_DWORD)v967 + 2;
                      i3 = -2007397661;
                    }
                    else
                    {
                      if ( i3 == -673330124 )
                      {
                        v181 = *((unsigned __int8 *)&unk_D407C0
                               + v1033
                               + (unsigned __int64)(unsigned int)((_DWORD)v967 + 3)) << 24;
                        *((_DWORD *)&v1046 + (unsigned int)v966) = v181 & v973 | (v973 | (v965 << 16)) ^ v181;
                        v179 = (_DWORD)v966 + 1;
                        v178 = (_DWORD)v967 + 4;
                        goto LABEL_198;
                      }
                      LODWORD(v967) = v178;
                      LODWORD(v966) = v179;
                      i3 = -1614485789;
                      if ( v178 < 0x40 )
                        i3 = -942669483;
                    }
                  }
                  if ( i3 != -2007397661 )
                    break;
                  v965 = *((_BYTE *)&unk_D407C0 + v1033 + (unsigned __int64)(unsigned int)v989);
                }
                v258 = v175 + __ROL4__((_DWORD)v1046 + (v177 & ~v175) + v174 + (v175 & v176) - 680876936, 7);
                v259 = v258 + __ROL4__(HIDWORD(v1046) + v177 + (v176 & ~v258) + (v175 & v258) - 389564586, 12);
                v981 = v174;
                v260 = v259 + __ROL4__((v258 & v259) + v176 + v1047 + (v175 & ~v259) + 606105819, 17);
                v261 = v260 + __ROL4__((v259 & v260) + v175 + HIDWORD(v1047) + (v258 & ~v260) - 1044525330, 22);
                v262 = v261 + __ROL4__((v260 & v261) + (v259 & ~v261) + v1048 + v258 - 176418897, 7);
                v263 = v262 + __ROL4__((v261 & v262) + (v260 & ~v262) + v1049 + v259 + 1200080426, 12);
                v264 = v263 + __ROL4__((v262 & v263) + (v261 & ~v263) + v1050 + v260 - 1473231341, 17);
                v265 = v264 + __ROL4__((v263 & v264) + (v262 & ~v264) + v1051 + v261 - 45705983, 22);
                v266 = v265 + __ROL4__((v264 & v265) + (v263 & ~v265) + v1052 + v262 + 1770035416, 7);
                v267 = v266 + __ROL4__((v264 & ~v266) + v1053 + v263 + (v265 & v266) - 1958414417, 12);
                v268 = v267 + __ROL4__((v266 & v267) + (v265 & ~v267) + v1054 + v264 - 42063, 17);
                v1007 = v175;
                v269 = v268 + __ROL4__((v266 & ~v268) + v1055 + v265 + (v267 & v268) - 1990404162, 22);
                v270 = v269 + __ROL4__((v267 & ~v269) + v1056 + v266 + (v268 & v269) + 1804603682, 7);
                v271 = v270 + __ROL4__((v268 & ~v270) + v1057 + v267 + (v269 & v270) - 40341101, 12);
                LODWORD(v985) = v177;
                v272 = v271 + __ROL4__((~v271 & v269) + v1058 + v268 + (v270 & v271) - 1502002290, 17);
                LODWORD(v1008) = v176;
                v273 = v272 + __ROL4__((v271 & v272) + (~v272 & v270) + v1059 + v269 + 1236535329, 22);
                v274 = v273 + __ROL4__(HIDWORD(v1046) + v270 + (v272 & ~v271) + (v271 & v273) - 165796510, 5);
                v275 = v274 + __ROL4__((v272 & v274) + (v273 & ~v272) + v1050 + v271 - 1069501632, 9);
                v276 = v275 + __ROL4__((v273 & v275) + (v274 & ~v273) + v1055 + v272 + 643717713, 14);
                v277 = v276 + __ROL4__((v275 & ~v274) + (_DWORD)v1046 + v273 + (v274 & v276) - 373897302, 20);
                v278 = v277 + __ROL4__((v275 & v277) + (v276 & ~v275) + v1049 + v274 - 701558691, 5);
                v279 = v278 + __ROL4__((v277 & ~v276) + v1054 + v275 + (v276 & v278) + 38016083, 9);
                v280 = v279 + __ROL4__((v277 & v279) + (v278 & ~v277) + v1059 + v276 - 660478335, 14);
                v281 = v280 + __ROL4__((v278 & v280) + (v279 & ~v278) + v1048 + v277 - 405537848, 20);
                v282 = v281 + __ROL4__((v279 & v281) + (v280 & ~v279) + v1053 + v278 + 568446438, 5);
                v283 = v282 + __ROL4__((v280 & v282) + (v281 & ~v280) + v1058 + v279 - 1019803690, 9);
                v284 = v283 + __ROL4__((v281 & v283) + (v282 & ~v281) + HIDWORD(v1047) + v280 - 187363961, 14);
                v285 = v284 + __ROL4__((v283 & ~v282) + v1052 + v281 + (v282 & v284) + 1163531501, 20);
                v286 = v285 + __ROL4__((v283 & v285) + (v284 & ~v283) + v1057 + v282 - 1444681467, 5);
                v287 = v286 + __ROL4__((v285 & ~v284) + v1047 + v283 + (v284 & v286) - 51403784, 9);
                v288 = v287 + __ROL4__((v285 & v287) + (v286 & ~v285) + v1051 + v284 + 1735328473, 14);
                v289 = v1049 + v286;
                v290 = v288 + __ROL4__((v286 & v288) + (v287 & ~v286) + v1056 + v285 - 1926607734, 20);
                v291 = v290 + __ROL4__(v289 + (v287 ^ v288 ^ v290) - 378558, 4);
                v292 = v291 + __ROL4__((v291 ^ v288 ^ v290) + v1052 + v287 - 2022574463, 11);
                v293 = v292 + __ROL4__((v290 ^ v291 ^ v292) + v1055 + v288 + 1839030562, 16);
                v294 = v293 + __ROL4__((v293 ^ v291 ^ v292) + v1058 + v290 - 35309556, 23);
                v295 = v294 + __ROL4__((v292 ^ v293 ^ v294) + HIDWORD(v1046) + v291 - 1530992060, 4);
                v296 = v295 + __ROL4__((v295 ^ v293 ^ v294) + v1048 + v292 + 1272893353, 11);
                v297 = v296 + __ROL4__((v294 ^ v295 ^ v296) + v1051 + v293 - 155497632, 16);
                v298 = v297 + __ROL4__((v297 ^ v295 ^ v296) + v1054 + v294 - 1094730640, 23);
                v299 = v298 + __ROL4__((v296 ^ v297 ^ v298) + v1057 + v295 + 681279174, 4);
                v300 = v299 + __ROL4__((v299 ^ v297 ^ v298) + (_DWORD)v1046 + v296 - 358537222, 11);
                v301 = v300 + __ROL4__((v300 ^ v298 ^ v299) + HIDWORD(v1047) + v297 - 722521979, 16);
                v302 = v301 + __ROL4__((v301 ^ v299 ^ v300) + v1050 + v298 + 76029189, 23);
                v303 = v302 + __ROL4__((v302 ^ v300 ^ v301) + v1053 + v299 - 640364487, 4);
                v304 = v303 + __ROL4__((v303 ^ v301 ^ v302) + v1056 + v300 - 421815835, 11);
                v305 = v304 + __ROL4__((v304 ^ v302 ^ v303) + v1059 + v301 + 530742520, 16);
                v306 = v305 + __ROL4__((v305 ^ v303 ^ v304) + v1047 + v302 - 995338651, 23);
                v307 = v306 + __ROL4__((v305 ^ (v306 | ~v304)) + (_DWORD)v1046 + v303 - 198630844, 6);
                v308 = v307 + __ROL4__(v1051 + v304 + (v306 ^ (v307 | ~v305)) + 1126891415, 10);
                v309 = v308 + __ROL4__((v307 ^ (v308 | ~v306)) + v1058 + v305 - 1416354905, 15);
                v310 = v309 + __ROL4__((v308 ^ (v309 | ~v307)) + v1049 + v306 - 57434055, 21);
                v311 = v310 + __ROL4__((v309 ^ (v310 | ~v308)) + v1056 + v307 + 1700485571, 6);
                v312 = v311 + __ROL4__((v310 ^ (v311 | ~v309)) + HIDWORD(v1047) + v308 - 1894986606, 10);
                v313 = v312 + __ROL4__((v311 ^ (~(v312 ^ v310) | v312 & ~v310)) + v1054 + v309 - 1051523, 15);
                v314 = v313 + __ROL4__((v312 ^ (v313 | ~v311)) + HIDWORD(v1046) + v310 - 2054922799, 21);
                v315 = v314 + __ROL4__((v313 ^ (v314 | ~v312)) + v1052 + v311 + 1873313359, 6);
                v316 = v315 + __ROL4__(v1059 + v312 + (v314 ^ (v315 | ~v313)) - 30611744, 10);
                v317 = v316 + __ROL4__((v315 ^ (~(v316 ^ v314) | v316 & ~v314)) + v1050 + v313 - 1560198380, 15);
                v318 = v317 + __ROL4__((v316 ^ (~(v315 ^ v317) | v317 & ~v315)) + v1057 + v314 + 1309151649, 21);
                v319 = v318 + __ROL4__(v1048 + v315 + (v317 ^ (v318 | ~v316)) - 145523070, 6);
                v320 = v319 + __ROL4__((v318 ^ (~(v319 ^ v317) | v319 & ~v317)) + v1055 + v316 - 1120210379, 10);
                v321 = v320 + __ROL4__(v1047 + v317 + (v319 ^ (v320 | ~v318)) + 718787259, 15);
                v322 = v1053 + v318;
                *(_DWORD *)v975 = v981 + v319;
                *((_DWORD *)v975 + 1) = __ROL4__(v322 + (v320 ^ (v321 | ~v319)) - 343485551, 21) + v321 + v175;
                *((_DWORD *)v975 + 2) = (_DWORD)v1008 + v321;
                *((_DWORD *)v975 + 3) = (_DWORD)v985 + v320;
                v323 = 0;
LABEL_259:
                v324 = 976919488;
                while ( 1 )
                {
                  while ( v324 <= -587301062 )
                  {
                    if ( v324 == -1016511951 )
                    {
                      v323 = (unsigned int)v967;
                      goto LABEL_259;
                    }
                    *((_BYTE *)&v1046 + (int)v966) = 0;
                    v324 = -455638576;
                  }
                  if ( v324 == -587301061 )
                    break;
                  if ( v324 == -455638576 )
                  {
                    LODWORD(v967) = (_DWORD)v966 + 1;
                    v324 = -1016511951;
                  }
                  else
                  {
                    LODWORD(v966) = v323;
                    v324 = -587301061;
                    if ( v323 < 0x40 )
                      v324 = -588599311;
                  }
                }
                v172 = v1033 + 64;
              }
              v1010 = v1009 - (_DWORD)v1013;
              for ( i4 = 0; ; i4 = (_DWORD)v966 + 1 )
              {
                for ( i5 = -1785266232; ; i5 = -1827872406 )
                {
                  while ( i5 <= -1207850492 )
                  {
                    if ( i5 == -1827872406 )
                    {
                      *((_BYTE *)v1046 + (_QWORD)&v1062[1] + (unsigned int)v1012) = *((_BYTE *)&unk_D407C0
                                                                                    + (_QWORD)v1046
                                                                                    + (unsigned int)v1013);
                      i5 = 976403079;
                    }
                    else
                    {
                      LODWORD(v966) = i4;
                      i5 = -554264179;
                      if ( i4 < v1010 )
                        i5 = -1207850491;
                    }
                  }
                  if ( i5 != -1207850491 )
                    break;
                  v1046 = (void *)(int)v966;
                }
                if ( i5 == -554264179 )
                  break;
              }
              v978 = v1062;
              v970 = v1062;
              v327 = v1062[0];
              v1004 = v1062[0];
              for ( i6 = -544619405; ; i6 = 848251583 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( i6 <= 848251582 )
                    {
                      if ( i6 <= -544619406 )
                      {
                        if ( i6 == -2109407181 )
                        {
                          i6 = 1843554541;
                          LODWORD(v985) = 0;
                          v1010 = v974;
                        }
                        else
                        {
                          i6 = 1843554541;
                          v1010 = 0;
                          LODWORD(v985) = v1033;
                        }
                      }
                      else if ( i6 == -544619405 )
                      {
                        v974 = (v1004 >> 3) & 0x3F;
                        i6 = -165828501;
                      }
                      else if ( i6 == -316297161 )
                      {
                        ++HIDWORD(v1062[0]);
                        i6 = 1066382172;
                      }
                      else
                      {
                        LODWORD(v1062[0]) = v1004 + 64;
                        i6 = 1066382172;
                        if ( v1004 >= 0xFFFFFFC0 )
                          i6 = -316297161;
                      }
                    }
                    if ( i6 > 1114565259 )
                      break;
                    if ( i6 == 848251583 )
                    {
                      v1033 = v327;
                      i6 = -785424894;
                      if ( v327 + 63 < 8 )
                        i6 = 1916821574;
                    }
                    else
                    {
                      v976 = 64 - v974;
                      i6 = 1114565260;
                      if ( 64 - v974 >= 9 )
                        i6 = -2109407181;
                    }
                  }
                  if ( i6 != 1114565260 )
                    break;
                  for ( i7 = 0; ; i7 = (_DWORD)v966 + 1 )
                  {
                    for ( i8 = -1785266232; ; i8 = -1827872406 )
                    {
                      while ( i8 <= -1207850492 )
                      {
                        if ( i8 == -1827872406 )
                        {
                          *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v974) = *((_BYTE *)&v1061[-1] + (_QWORD)v1046);
                          i8 = 976403079;
                        }
                        else
                        {
                          LODWORD(v966) = i7;
                          i8 = -554264179;
                          if ( i7 < v976 )
                            i8 = -1207850491;
                        }
                      }
                      if ( i8 != -1207850491 )
                        break;
                      v1046 = (void *)(int)v966;
                    }
                    if ( i8 == -554264179 )
                      break;
                  }
                  v975 = v1061;
                  v340 = (int)v1061[0];
                  v341 = HIDWORD(v1061[0]);
                  v342 = (int)v1061[1];
                  v1013 = v1061;
                  v343 = HIDWORD(v1061[1]);
                  v344 = 0;
                  v345 = 0;
LABEL_332:
                  for ( i9 = 496118048; ; i9 = -673330124 )
                  {
                    while ( i9 > -942669484 )
                    {
                      if ( i9 == -942669483 )
                      {
                        v973 = *((unsigned __int8 *)&v1062[1] + (unsigned int)v967)
                             | (*((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 1)) << 8);
                        LODWORD(v989) = (_DWORD)v967 + 2;
                        i9 = -2007397661;
                      }
                      else
                      {
                        if ( i9 == -673330124 )
                        {
                          v347 = *((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 3)) << 24;
                          *((_DWORD *)&v1046 + (unsigned int)v966) = v347 & v973 | (v973 | (v965 << 16)) ^ v347;
                          v345 = (_DWORD)v966 + 1;
                          v344 = (_DWORD)v967 + 4;
                          goto LABEL_332;
                        }
                        LODWORD(v967) = v344;
                        LODWORD(v966) = v345;
                        i9 = -1614485789;
                        if ( v344 < 0x40 )
                          i9 = -942669483;
                      }
                    }
                    if ( i9 != -2007397661 )
                      break;
                    v965 = *((_BYTE *)&v1062[1] + (unsigned int)v989);
                  }
                  v348 = v341 + __ROL4__((_DWORD)v1046 + (v343 & ~v341) + v340 + (v341 & v342) - 680876936, 7);
                  v1007 = v341;
                  v349 = v348 + __ROL4__(HIDWORD(v1046) + v343 + (v342 & ~v348) + (v341 & v348) - 389564586, 12);
                  v982 = v343;
                  v350 = v349 + __ROL4__(v1047 + v342 + (v341 & ~v349) + (v348 & v349) + 606105819, 17);
                  v351 = v350 + __ROL4__(HIDWORD(v1047) + v341 + (v348 & ~v350) + (v349 & v350) - 1044525330, 22);
                  v352 = v351 + __ROL4__((v350 & v351) + (v349 & ~v351) + v1048 + v348 - 176418897, 7);
                  v353 = v352 + __ROL4__((v351 & v352) + (v350 & ~v352) + v1049 + v349 + 1200080426, 12);
                  v354 = v353 + __ROL4__((v352 & v353) + (v351 & ~v353) + v1050 + v350 - 1473231341, 17);
                  v355 = v354 + __ROL4__((v353 & v354) + (v352 & ~v354) + v1051 + v351 - 45705983, 22);
                  v356 = v355 + __ROL4__((v354 & v355) + (v353 & ~v355) + v1052 + v352 + 1770035416, 7);
                  v357 = v356 + __ROL4__((v355 & v356) + (v354 & ~v356) + v1053 + v353 - 1958414417, 12);
                  v358 = v357 + __ROL4__((v356 & v357) + (v355 & ~v357) + v1054 + v354 - 42063, 17);
                  v359 = v358 + __ROL4__((v357 & v358) + (v356 & ~v358) + v1055 + v355 - 1990404162, 22);
                  v360 = v359 + __ROL4__((v358 & v359) + (v357 & ~v359) + v1056 + v356 + 1804603682, 7);
                  v361 = v360 + __ROL4__((v358 & ~v360) + v1057 + v357 + (v359 & v360) - 40341101, 12);
                  LODWORD(v1012) = v342;
                  LODWORD(v1008) = v340;
                  v362 = v361 + __ROL4__((~v361 & v359) + v1058 + v358 + (v360 & v361) - 1502002290, 17);
                  v363 = v362 + __ROL4__((v361 & v362) + (~v362 & v360) + v1059 + v359 + 1236535329, 22);
                  v364 = v363 + __ROL4__((v361 & v363) + v360 + HIDWORD(v1046) + (v362 & ~v361) - 165796510, 5);
                  v365 = v364 + __ROL4__((v362 & v364) + (v363 & ~v362) + v1050 + v361 - 1069501632, 9);
                  v366 = v365 + __ROL4__((v363 & v365) + (v364 & ~v363) + v1055 + v362 + 643717713, 14);
                  v367 = v366 + __ROL4__((v364 & v366) + (v365 & ~v364) + (_DWORD)v1046 + v363 - 373897302, 20);
                  v368 = v367 + __ROL4__((v365 & v367) + (v366 & ~v365) + v1049 + v364 - 701558691, 5);
                  v369 = v368 + __ROL4__((v366 & v368) + (v367 & ~v366) + v1054 + v365 + 38016083, 9);
                  v370 = v369 + __ROL4__((v367 & v369) + (v368 & ~v367) + v1059 + v366 - 660478335, 14);
                  v371 = v370 + __ROL4__((v368 & v370) + (v369 & ~v368) + v1048 + v367 - 405537848, 20);
                  v372 = v371 + __ROL4__((v369 & v371) + (v370 & ~v369) + v1053 + v368 + 568446438, 5);
                  v373 = v372 + __ROL4__((v370 & v372) + (v371 & ~v370) + v1058 + v369 - 1019803690, 9);
                  v374 = v373 + __ROL4__((v371 & v373) + (v372 & ~v371) + HIDWORD(v1047) + v370 - 187363961, 14);
                  v375 = v374 + __ROL4__((v372 & v374) + (v373 & ~v372) + v1052 + v371 + 1163531501, 20);
                  v376 = v375 + __ROL4__((v373 & v375) + (v374 & ~v373) + v1057 + v372 - 1444681467, 5);
                  v377 = v376 + __ROL4__((v374 & v376) + (v375 & ~v374) + v1047 + v373 - 51403784, 9);
                  v378 = v377 + __ROL4__((v375 & v377) + (v376 & ~v375) + v1051 + v374 + 1735328473, 14);
                  v379 = v378 + __ROL4__((v376 & v378) + (v377 & ~v376) + v1056 + v375 - 1926607734, 20);
                  v380 = v379 + __ROL4__((v377 ^ v378 ^ v379) + v1049 + v376 - 378558, 4);
                  v381 = v380 + __ROL4__((v380 ^ v378 ^ v379) + v1052 + v377 - 2022574463, 11);
                  v382 = v381 + __ROL4__((v379 ^ v380 ^ v381) + v1055 + v378 + 1839030562, 16);
                  v383 = v382 + __ROL4__((v382 ^ v380 ^ v381) + v1058 + v379 - 35309556, 23);
                  v384 = v383 + __ROL4__(HIDWORD(v1046) + v380 + (v381 ^ v382 ^ v383) - 1530992060, 4);
                  v385 = v384 + __ROL4__(v1048 + v381 + (v384 ^ v382 ^ v383) + 1272893353, 11);
                  v386 = v385 + __ROL4__((v383 ^ v384 ^ v385) + v1051 + v382 - 155497632, 16);
                  v387 = v386 + __ROL4__((v386 ^ v384 ^ v385) + v1054 + v383 - 1094730640, 23);
                  v388 = v387 + __ROL4__((v385 ^ v386 ^ v387) + v1057 + v384 + 681279174, 4);
                  v389 = v388 + __ROL4__((v388 ^ v386 ^ v387) + (_DWORD)v1046 + v385 - 358537222, 11);
                  v390 = v389 + __ROL4__((v389 ^ v387 ^ v388) + HIDWORD(v1047) + v386 - 722521979, 16);
                  v391 = v390 + __ROL4__((v390 ^ v388 ^ v389) + v1050 + v387 + 76029189, 23);
                  v392 = v391 + __ROL4__((v391 ^ v389 ^ v390) + v1053 + v388 - 640364487, 4);
                  v393 = v392 + __ROL4__((v392 ^ v390 ^ v391) + v1056 + v389 - 421815835, 11);
                  v394 = v393 + __ROL4__((v393 ^ v391 ^ v392) + v1059 + v390 + 530742520, 16);
                  v395 = v394 + __ROL4__((v394 ^ v392 ^ v393) + v1047 + v391 - 995338651, 23);
                  v396 = v395 + __ROL4__((v394 ^ (v395 | ~v393)) + (_DWORD)v1046 + v392 - 198630844, 6);
                  v397 = v396 + __ROL4__((v395 ^ (v396 | ~v394)) + v1051 + v393 + 1126891415, 10);
                  v398 = v397 + __ROL4__((v396 ^ (v397 | ~v395)) + v1058 + v394 - 1416354905, 15);
                  v399 = v398 + __ROL4__((v397 ^ (v398 | ~v396)) + v1049 + v395 - 57434055, 21);
                  v400 = v399 + __ROL4__((v398 ^ (v399 | ~v397)) + v1056 + v396 + 1700485571, 6);
                  v401 = v400 + __ROL4__(HIDWORD(v1047) + v397 + (v399 ^ (v400 | ~v398)) - 1894986606, 10);
                  v402 = v401 + __ROL4__((v400 ^ (~(v401 ^ v399) | v401 & ~v399)) + v1054 + v398 - 1051523, 15);
                  v403 = v402 + __ROL4__((v401 ^ (v402 | ~v400)) + HIDWORD(v1046) + v399 - 2054922799, 21);
                  v404 = v403 + __ROL4__((v402 ^ (v403 | ~v401)) + v1052 + v400 + 1873313359, 6);
                  v405 = v404 + __ROL4__(v1059 + v401 + (v403 ^ (v404 | ~v402)) - 30611744, 10);
                  v406 = v405 + __ROL4__((v404 ^ (~(v405 ^ v403) | v405 & ~v403)) + v1050 + v402 - 1560198380, 15);
                  v407 = v406 + __ROL4__((v405 ^ (~(v404 ^ v406) | v406 & ~v404)) + v1057 + v403 + 1309151649, 21);
                  v408 = v407 + __ROL4__(v1048 + v404 + (v406 ^ (v407 | ~v405)) - 145523070, 6);
                  v409 = v408 + __ROL4__((v407 ^ (~(v408 ^ v406) | v408 & ~v406)) + v1055 + v405 - 1120210379, 10);
                  v410 = v409 + __ROL4__(v1047 + v406 + (v408 ^ (v409 | ~v407)) + 718787259, 15);
                  LODWORD(v1061[0]) = (_DWORD)v1008 + v408;
                  HIDWORD(v1061[0]) = __ROL4__((v409 ^ (v410 | ~v408)) + v1053 + v407 - 343485551, 21) + v410 + v1007;
                  LODWORD(v1061[1]) = v1012 + v410;
                  HIDWORD(v1061[1]) = v982 + v409;
                  v411 = 0;
LABEL_344:
                  v412 = 976919488;
                  while ( 1 )
                  {
                    while ( v412 <= -587301062 )
                    {
                      if ( v412 == -1016511951 )
                      {
                        v411 = (unsigned int)v967;
                        goto LABEL_344;
                      }
                      *((_BYTE *)&v1046 + (int)v966) = 0;
                      v412 = -455638576;
                    }
                    if ( v412 == -587301061 )
                      break;
                    if ( v412 == -455638576 )
                    {
                      LODWORD(v967) = (_DWORD)v966 + 1;
                      v412 = -1016511951;
                    }
                    else
                    {
                      LODWORD(v966) = v411;
                      v412 = -587301061;
                      if ( v411 < 0x40 )
                        v412 = -588599311;
                    }
                  }
                  i6 = 848251583;
                  v327 = v976;
                }
                if ( i6 != 1916821574 )
                  break;
                v329 = (char *)&v1061[-1] + v1033;
                v330 = *(_DWORD *)v975;
                v331 = *((_DWORD *)v975 + 1);
                v332 = *((_DWORD *)v975 + 2);
                LODWORD(v1013) = (_DWORD)v975;
                v333 = *((_DWORD *)v975 + 3);
                v334 = 0;
                v335 = 0;
LABEL_295:
                for ( i10 = 496118048; ; i10 = -673330124 )
                {
                  while ( i10 > -942669484 )
                  {
                    if ( i10 == -942669483 )
                    {
                      v973 = (unsigned __int8)v329[(unsigned int)v967] | ((unsigned __int8)v329[(_DWORD)v967 + 1] << 8);
                      LODWORD(v989) = (_DWORD)v967 + 2;
                      i10 = -2007397661;
                    }
                    else
                    {
                      if ( i10 == -673330124 )
                      {
                        v337 = (unsigned __int8)v329[(_DWORD)v967 + 3] << 24;
                        *((_DWORD *)&v1046 + (unsigned int)v966) = v337 & v973 | (v973 | (v965 << 16)) ^ v337;
                        v335 = (_DWORD)v966 + 1;
                        v334 = (_DWORD)v967 + 4;
                        goto LABEL_295;
                      }
                      LODWORD(v967) = v334;
                      LODWORD(v966) = v335;
                      i10 = -1614485789;
                      if ( v334 < 0x40 )
                        i10 = -942669483;
                    }
                  }
                  if ( i10 != -2007397661 )
                    break;
                  v965 = v329[(unsigned int)v989];
                }
                v413 = v331 + __ROL4__((_DWORD)v1046 + (v333 & ~v331) + v330 + (v331 & v332) - 680876936, 7);
                v414 = v413 + __ROL4__(HIDWORD(v1046) + v333 + (v332 & ~v413) + (v331 & v413) - 389564586, 12);
                LODWORD(v1012) = v331;
                v415 = v414 + __ROL4__(v332 + v1047 + (v331 & ~v414) + (v413 & v414) + 606105819, 17);
                v416 = v415 + __ROL4__((v414 & v415) + HIDWORD(v1047) + v331 + (v413 & ~v415) - 1044525330, 22);
                v417 = v416 + __ROL4__((v415 & v416) + (v414 & ~v416) + v1048 + v413 - 176418897, 7);
                v418 = v417 + __ROL4__((v416 & v417) + (v415 & ~v417) + v1049 + v414 + 1200080426, 12);
                v419 = v418 + __ROL4__((v417 & v418) + (v416 & ~v418) + v1050 + v415 - 1473231341, 17);
                v420 = v419 + __ROL4__((v418 & v419) + (v417 & ~v419) + v1051 + v416 - 45705983, 22);
                v421 = v420 + __ROL4__((v418 & ~v420) + v1052 + v417 + (v419 & v420) + 1770035416, 7);
                v422 = v421 + __ROL4__((v420 & v421) + (v419 & ~v421) + v1053 + v418 - 1958414417, 12);
                v423 = v422 + __ROL4__((v421 & v422) + (v420 & ~v422) + v1054 + v419 - 42063, 17);
                v424 = v423 + __ROL4__((v422 & v423) + (v421 & ~v423) + v1055 + v420 - 1990404162, 22);
                v425 = v424 + __ROL4__((v423 & v424) + (v422 & ~v424) + v1056 + v421 + 1804603682, 7);
                v426 = v425 + __ROL4__((v423 & ~v425) + v1057 + v422 + (v424 & v425) - 40341101, 12);
                LODWORD(v1008) = v333;
                v427 = v426 + __ROL4__((~v426 & v424) + v1058 + v423 + (v425 & v426) - 1502002290, 17);
                v1007 = v332;
                v997 = v330;
                v428 = v427 + __ROL4__((v426 & v427) + (~v427 & v425) + v1059 + v424 + 1236535329, 22);
                v429 = v428 + __ROL4__((v426 & v428) + HIDWORD(v1046) + v425 + (v427 & ~v426) - 165796510, 5);
                v430 = v429 + __ROL4__((v427 & v429) + (v428 & ~v427) + v1050 + v426 - 1069501632, 9);
                v431 = v430 + __ROL4__((v428 & v430) + (v429 & ~v428) + v1055 + v427 + 643717713, 14);
                v432 = v431 + __ROL4__((v429 & v431) + (v430 & ~v429) + (_DWORD)v1046 + v428 - 373897302, 20);
                v433 = v432 + __ROL4__((v430 & v432) + (v431 & ~v430) + v1049 + v429 - 701558691, 5);
                v434 = v433 + __ROL4__((v431 & v433) + (v432 & ~v431) + v1054 + v430 + 38016083, 9);
                v435 = v434 + __ROL4__((v432 & v434) + (v433 & ~v432) + v1059 + v431 - 660478335, 14);
                v436 = v435 + __ROL4__((v433 & v435) + (v434 & ~v433) + v1048 + v432 - 405537848, 20);
                v437 = v436 + __ROL4__((v434 & v436) + (v435 & ~v434) + v1053 + v433 + 568446438, 5);
                v438 = v437 + __ROL4__((v435 & v437) + (v436 & ~v435) + v1058 + v434 - 1019803690, 9);
                v439 = v438 + __ROL4__((v436 & v438) + (v437 & ~v436) + HIDWORD(v1047) + v435 - 187363961, 14);
                v440 = v439 + __ROL4__((v437 & v439) + (v438 & ~v437) + v1052 + v436 + 1163531501, 20);
                v441 = v440 + __ROL4__((v438 & v440) + (v439 & ~v438) + v1057 + v437 - 1444681467, 5);
                v442 = v441 + __ROL4__((v439 & v441) + (v440 & ~v439) + v1047 + v438 - 51403784, 9);
                v443 = v442 + __ROL4__((v440 & v442) + (v441 & ~v440) + v1051 + v439 + 1735328473, 14);
                v444 = v443 + __ROL4__((v441 & v443) + (v442 & ~v441) + v1056 + v440 - 1926607734, 20);
                v445 = v444 + __ROL4__((v442 ^ v443 ^ v444) + v1049 + v441 - 378558, 4);
                v446 = v445 + __ROL4__((v445 ^ v443 ^ v444) + v1052 + v442 - 2022574463, 11);
                v447 = v446 + __ROL4__((v444 ^ v445 ^ v446) + v1055 + v443 + 1839030562, 16);
                v448 = v447 + __ROL4__((v447 ^ v445 ^ v446) + v1058 + v444 - 35309556, 23);
                v449 = v448 + __ROL4__((v446 ^ v447 ^ v448) + HIDWORD(v1046) + v445 - 1530992060, 4);
                v450 = v449 + __ROL4__((v449 ^ v447 ^ v448) + v1048 + v446 + 1272893353, 11);
                v451 = v450 + __ROL4__(v1051 + v447 + (v448 ^ v449 ^ v450) - 155497632, 16);
                v452 = v451 + __ROL4__((v451 ^ v449 ^ v450) + v1054 + v448 - 1094730640, 23);
                v453 = v452 + __ROL4__(v1057 + v449 + (v450 ^ v451 ^ v452) + 681279174, 4);
                v454 = v453 + __ROL4__((v453 ^ v451 ^ v452) + (_DWORD)v1046 + v450 - 358537222, 11);
                v455 = v454 + __ROL4__((v454 ^ v452 ^ v453) + HIDWORD(v1047) + v451 - 722521979, 16);
                v456 = v455 + __ROL4__(v1050 + v452 + (v455 ^ v453 ^ v454) + 76029189, 23);
                v457 = v456 + __ROL4__((v456 ^ v454 ^ v455) + v1053 + v453 - 640364487, 4);
                v458 = v457 + __ROL4__((v457 ^ v455 ^ v456) + v1056 + v454 - 421815835, 11);
                v459 = v458 + __ROL4__(v1059 + v455 + (v458 ^ v456 ^ v457) + 530742520, 16);
                v460 = v459 + __ROL4__((v459 ^ v457 ^ v458) + v1047 + v456 - 995338651, 23);
                v461 = v460 + __ROL4__((v459 ^ (v460 | ~v458)) + (_DWORD)v1046 + v457 - 198630844, 6);
                v462 = v461 + __ROL4__((v460 ^ (v461 | ~v459)) + v1051 + v458 + 1126891415, 10);
                v463 = v462 + __ROL4__((v461 ^ (v462 | ~v460)) + v1058 + v459 - 1416354905, 15);
                v464 = v463 + __ROL4__((v462 ^ (v463 | ~v461)) + v1049 + v460 - 57434055, 21);
                v465 = v464 + __ROL4__((v463 ^ (v464 | ~v462)) + v1056 + v461 + 1700485571, 6);
                v466 = v465 + __ROL4__((v464 ^ (v465 | ~v463)) + HIDWORD(v1047) + v462 - 1894986606, 10);
                v467 = v466 + __ROL4__(v1054 + v463 + (v465 ^ (~(v466 ^ v464) | v466 & ~v464)) - 1051523, 15);
                v468 = v467 + __ROL4__((v466 ^ (v467 | ~v465)) + HIDWORD(v1046) + v464 - 2054922799, 21);
                v469 = v468 + __ROL4__(v1052 + v465 + (v467 ^ (v468 | ~v466)) + 1873313359, 6);
                v470 = v469 + __ROL4__((v468 ^ (v469 | ~v467)) + v1059 + v466 - 30611744, 10);
                v471 = v470 + __ROL4__((v469 ^ (~(v470 ^ v468) | v470 & ~v468)) + v1050 + v467 - 1560198380, 15);
                v472 = v471 + __ROL4__(v1057 + v468 + (v470 ^ (~(v469 ^ v471) | v471 & ~v469)) + 1309151649, 21);
                v473 = v472 + __ROL4__((v471 ^ (v472 | ~v470)) + v1048 + v469 - 145523070, 6);
                v474 = v473 + __ROL4__((v472 ^ (~(v473 ^ v471) | v473 & ~v471)) + v1055 + v470 - 1120210379, 10);
                v475 = v474 + __ROL4__((v473 ^ (v474 | ~v472)) + v1047 + v471 + 718787259, 15);
                v476 = (v474 ^ (v475 | ~v473)) + v1053 + v472 - 343485551;
                *(_DWORD *)v975 = v997 + v473;
                *((_DWORD *)v975 + 1) = __ROL4__(v476, 21) + v475 + v1012;
                *((_DWORD *)v975 + 2) = v1007 + v475;
                *((_DWORD *)v975 + 3) = (_DWORD)v1008 + v474;
                v477 = 0;
LABEL_356:
                v478 = 976919488;
                while ( 1 )
                {
                  while ( v478 <= -587301062 )
                  {
                    if ( v478 == -1016511951 )
                    {
                      v477 = (unsigned int)v967;
                      goto LABEL_356;
                    }
                    *((_BYTE *)&v1046 + (int)v966) = 0;
                    v478 = -455638576;
                  }
                  if ( v478 == -587301061 )
                    break;
                  if ( v478 == -455638576 )
                  {
                    LODWORD(v967) = (_DWORD)v966 + 1;
                    v478 = -1016511951;
                  }
                  else
                  {
                    LODWORD(v966) = v477;
                    v478 = -587301061;
                    if ( v477 < 0x40 )
                      v478 = -588599311;
                  }
                }
                v327 = v1033 + 64;
              }
              for ( i11 = 0; ; i11 = (_DWORD)v966 + 1 )
              {
                for ( i12 = -1785266232; ; i12 = -1827872406 )
                {
                  while ( i12 <= -1207850492 )
                  {
                    if ( i12 == -1827872406 )
                    {
                      *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v1010) = *((_BYTE *)&v1061[-1]
                                                                      + (_QWORD)v1046
                                                                      + (unsigned int)v985);
                      i12 = 976403079;
                    }
                    else
                    {
                      LODWORD(v966) = i11;
                      i12 = -554264179;
                      if ( i11 < 8 - (int)v985 )
                        i12 = -1207850491;
                    }
                  }
                  if ( i12 != -1207850491 )
                    break;
                  v1046 = (void *)(int)v966;
                }
                if ( i12 == -554264179 )
                  break;
              }
              v481 = 0;
              v482 = 0;
LABEL_381:
              for ( i13 = -1717192363; ; i13 = -2031488434 )
              {
                while ( 1 )
                {
                  while ( i13 <= -736119120 )
                  {
                    if ( i13 == -2031488434 )
                    {
                      *((_BYTE *)ptr + (unsigned int)v978) = (_BYTE)v966;
                      v482 = (_DWORD)v975 + 1;
                      v481 = (_DWORD)v970 + 4;
                      goto LABEL_381;
                    }
                    LODWORD(v970) = v481;
                    LODWORD(v975) = v482;
                    i13 = 494299060;
                    if ( v481 < 0x10 )
                      i13 = -736119119;
                  }
                  if ( i13 != -736119119 )
                    break;
                  v1046 = (char *)v1061 + 4 * (unsigned int)v975;
                  *((_BYTE *)ptr + (unsigned int)v970) = *(_BYTE *)v1046;
                  *((_BYTE *)ptr + (unsigned int)((_DWORD)v970 + 1)) = *((_BYTE *)v1046 + 1);
                  *((_BYTE *)ptr + (unsigned int)((_DWORD)v970 + 2)) = *((_BYTE *)v1046 + 2);
                  i13 = 1223234202;
                }
                if ( i13 == 494299060 )
                  break;
                LOBYTE(v966) = *((_BYTE *)v1046 + 3);
                LODWORD(v978) = (_DWORD)v970 + 3;
              }
              v484 = 0;
LABEL_393:
              v485 = 976919488;
              while ( 1 )
              {
                while ( v485 <= -587301062 )
                {
                  if ( v485 == -1016511951 )
                  {
                    v484 = (unsigned int)v975;
                    goto LABEL_393;
                  }
                  *((_BYTE *)v1061 + (int)v1046) = 0;
                  v485 = -455638576;
                }
                if ( v485 == -587301061 )
                  break;
                if ( v485 == -455638576 )
                {
                  LODWORD(v975) = (_DWORD)v1046 + 1;
                  v485 = -1016511951;
                }
                else
                {
                  LODWORD(v1046) = v484;
                  v485 = -587301061;
                  if ( v484 < 0x58 )
                    v485 = -588599311;
                }
              }
              LOBYTE(v978) = 0;
              for ( i14 = 486138542; i14 != 55239270; i14 = 55239270 )
                ;
              for ( i15 = 0; ; i15 = (_DWORD)v975 + 1 )
              {
                for ( i16 = -1785266232; ; i16 = -1827872406 )
                {
                  while ( i16 <= -1207850492 )
                  {
                    if ( i16 == -1827872406 )
                    {
                      v1044[(_QWORD)v1046] = *((_BYTE *)ptr + (_QWORD)v1046);
                      i16 = 976403079;
                    }
                    else
                    {
                      LODWORD(v975) = i15;
                      i16 = -554264179;
                      if ( i15 < 0x10 )
                        i16 = -1207850491;
                    }
                  }
                  if ( i16 != -1207850491 )
                    break;
                  v1046 = (void *)(int)v975;
                }
                if ( i16 == -554264179 )
                  break;
              }
              *a1 = v1026;
              std::string::_M_construct<char const*>(a1, v1044, ptr);
              LODWORD(v4) = -1469387901;
              break;
            case 0xF1377DF9:
              v6 = *(_DWORD *)(sub_56C2E3E() + 160) == 1;
              LODWORD(v4) = 1686634351;
              if ( v6 )
                LODWORD(v4) = -390622148;
              break;
          }
        }
      }
      if ( (int)v4 > 1686634350 )
        break;
      if ( (_DWORD)v4 == (_DWORD)&unk_1039CDE )
      {
        LODWORD(v4) = -248021511;
        if ( !a3[1] )
          LODWORD(v4) = 1686634351;
      }
      else if ( (_DWORD)v4 == 127093981 )
      {
        *a1 = v1026;
        v11 = sub_56F9F18(&buf);
        std::string::_M_construct<char const*>(a1, &buf, &buf + v11);
        LODWORD(v4) = 2111984431;
      }
      else if ( (_DWORD)v4 == 451461577 )
      {
        sub_56C3008(v1040, a2, a4);
        v1061[0] = v1062;
        std::string::_M_construct<char *>(v1061, v1042[0], (char *)v1042[0] + (unsigned __int64)v1042[1]);
        std::string::_M_append(v1061, v1040[0], v1040[1]);
        v5 = (__int128 **)std::string::_M_append(v1061, *a4, a4[1]);
        v1037 = &v1039;
        if ( *v5 == (__int128 *)(v5 + 2) )
        {
          v1039 = **v5;
        }
        else
        {
          v1037 = *v5;
          *(_QWORD *)&v1039 = v5[2];
        }
        v1038 = v5[1];
        *v5 = (__int128 *)(v5 + 2);
        v5[1] = 0;
        *((_BYTE *)v5 + 16) = 0;
        if ( v1061[0] != v1062 )
          operator delete(v1061[0]);
        v1036 = 0;
        v1030 = &v1036;
        v1021 = ptr;
        *(_OWORD *)ptr = 0;
        v1024 = v1061;
        v1062[0] = 0;
        *(_OWORD *)v1061 = xmmword_9EA8F0;
        v1011 = (char *)v1037;
        v980 = v1062;
        v971 = v1062;
        v977 = 0;
        v1019 = (unsigned int)v1038 >> 29;
        v986 = (unsigned int)v1038;
        v489 = 8 * (_DWORD)v1038;
        v1023 = 8 * (_DWORD)v1038;
        for ( i17 = -544619405; ; i17 = 848251583 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( i17 <= 848251582 )
              {
                if ( i17 <= -544619406 )
                {
                  if ( i17 == -2109407181 )
                  {
                    i17 = 1843554541;
                    LODWORD(v1013) = 0;
                    LODWORD(v1012) = v1033;
                  }
                  else
                  {
                    i17 = 1843554541;
                    LODWORD(v1012) = 0;
                    LODWORD(v1013) = (_DWORD)v989;
                  }
                }
                else if ( i17 == -544619405 )
                {
                  v1033 = 0;
                  i17 = -165828501;
                }
                else
                {
                  LODWORD(v1062[0]) = v1023;
                  i17 = 1066382172;
                }
              }
              if ( i17 > 1114565259 )
                break;
              if ( i17 == 848251583 )
              {
                LODWORD(v989) = v489;
                i17 = -785424894;
                if ( v489 + 63 < v986 )
                  i17 = 1916821574;
              }
              else
              {
                HIDWORD(v1062[0]) += v1019;
                v973 = 64 - v1033;
                i17 = 1114565260;
                if ( 64 - v1033 > v986 )
                  i17 = -2109407181;
              }
            }
            if ( i17 != 1114565260 )
              break;
            for ( i18 = 0; ; i18 = (_DWORD)v968 + 1 )
            {
              for ( i19 = -1785266232; ; i19 = -1827872406 )
              {
                while ( i19 <= -1207850492 )
                {
                  if ( i19 == -1827872406 )
                  {
                    *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v1033) = *((_BYTE *)v1046 + (_QWORD)v1011);
                    i19 = 976403079;
                  }
                  else
                  {
                    LODWORD(v968) = i18;
                    i19 = -554264179;
                    if ( i18 < v973 )
                      i19 = -1207850491;
                  }
                }
                if ( i19 != -1207850491 )
                  break;
                v1046 = (void *)(int)v968;
              }
              if ( i19 == -554264179 )
                break;
            }
            v975 = v1061;
            v502 = (int)v1061[0];
            v503 = HIDWORD(v1061[0]);
            v504 = (int)v1061[1];
            v1008 = v1061;
            v505 = HIDWORD(v1061[1]);
            v506 = 0;
            v507 = 0;
LABEL_473:
            for ( i20 = 496118048; ; i20 = -673330124 )
            {
              while ( i20 > -942669484 )
              {
                if ( i20 == -942669483 )
                {
                  LODWORD(v967) = *((unsigned __int8 *)&v1062[1] + (unsigned int)v1060)
                                | (*((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v1060 + 1)) << 8);
                  LODWORD(v966) = (_DWORD)v1060 + 2;
                  i20 = -2007397661;
                }
                else
                {
                  if ( i20 == -673330124 )
                  {
                    v509 = *((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v1060 + 3)) << 24;
                    *((_DWORD *)&v1046 + (unsigned int)v968) = v509 & (unsigned int)v967
                                                             | ((unsigned int)v967 | ((unsigned __int8)v974 << 16))
                                                             ^ v509;
                    v507 = (_DWORD)v968 + 1;
                    v506 = (_DWORD)v1060 + 4;
                    goto LABEL_473;
                  }
                  LODWORD(v1060) = v506;
                  LODWORD(v968) = v507;
                  i20 = -1614485789;
                  if ( v506 < 0x40 )
                    i20 = -942669483;
                }
              }
              if ( i20 != -2007397661 )
                break;
              LOBYTE(v974) = *((_BYTE *)&v1062[1] + (unsigned int)v966);
            }
            v510 = v503 + __ROL4__((_DWORD)v1046 + (v505 & ~v503) + v502 + (v503 & v504) - 680876936, 7);
            v511 = v510 + __ROL4__((v503 & v510) + v505 + HIDWORD(v1046) + (v504 & ~v510) - 389564586, 12);
            v1007 = v505;
            v512 = v511 + __ROL4__((v510 & v511) + v1047 + v504 + (v503 & ~v511) + 606105819, 17);
            v513 = v512 + __ROL4__((v511 & v512) + v503 + HIDWORD(v1047) + (v510 & ~v512) - 1044525330, 22);
            v514 = v513 + __ROL4__((v512 & v513) + (v511 & ~v513) + v1048 + v510 - 176418897, 7);
            v515 = v514 + __ROL4__((v513 & v514) + (v512 & ~v514) + v1049 + v511 + 1200080426, 12);
            v516 = v515 + __ROL4__((v514 & v515) + (v513 & ~v515) + v1050 + v512 - 1473231341, 17);
            v517 = v516 + __ROL4__((v515 & v516) + (v514 & ~v516) + v1051 + v513 - 45705983, 22);
            v518 = v517 + __ROL4__((v515 & ~v517) + v1052 + v514 + (v516 & v517) + 1770035416, 7);
            v998 = v504;
            v519 = v518 + __ROL4__((v517 & v518) + (v516 & ~v518) + v1053 + v515 - 1958414417, 12);
            v520 = v519 + __ROL4__((v518 & v519) + (v517 & ~v519) + v1054 + v516 - 42063, 17);
            v521 = v520 + __ROL4__((v519 & v520) + (v518 & ~v520) + v1055 + v517 - 1990404162, 22);
            v992 = v502;
            v522 = v521 + __ROL4__((v520 & v521) + (v519 & ~v521) + v1056 + v518 + 1804603682, 7);
            v523 = v522 + __ROL4__((v521 & v522) + (v520 & ~v522) + v1057 + v519 - 40341101, 12);
            v524 = v523 + __ROL4__((v522 & v523) + (~v523 & v521) + v1058 + v520 - 1502002290, 17);
            v525 = v524 + __ROL4__((~v524 & v522) + v1059 + v521 + (v523 & v524) + 1236535329, 22);
            v526 = v525 + __ROL4__((v523 & v525) + v522 + HIDWORD(v1046) + (v524 & ~v523) - 165796510, 5);
            v527 = v526 + __ROL4__((v524 & v526) + (v525 & ~v524) + v1050 + v523 - 1069501632, 9);
            v528 = v527 + __ROL4__((v525 & v527) + (v526 & ~v525) + v1055 + v524 + 643717713, 14);
            v529 = v528 + __ROL4__((v526 & v528) + (v527 & ~v526) + (_DWORD)v1046 + v525 - 373897302, 20);
            v530 = v529 + __ROL4__((v527 & v529) + (v528 & ~v527) + v1049 + v526 - 701558691, 5);
            v531 = v530 + __ROL4__((v528 & v530) + (v529 & ~v528) + v1054 + v527 + 38016083, 9);
            v532 = v531 + __ROL4__((v529 & v531) + (v530 & ~v529) + v1059 + v528 - 660478335, 14);
            v533 = v532 + __ROL4__((v530 & v532) + (v531 & ~v530) + v1048 + v529 - 405537848, 20);
            v534 = v533 + __ROL4__((v531 & v533) + (v532 & ~v531) + v1053 + v530 + 568446438, 5);
            v535 = v534 + __ROL4__((v532 & v534) + (v533 & ~v532) + v1058 + v531 - 1019803690, 9);
            v536 = v535 + __ROL4__((v533 & v535) + (v534 & ~v533) + HIDWORD(v1047) + v532 - 187363961, 14);
            v537 = v536 + __ROL4__((v534 & v536) + (v535 & ~v534) + v1052 + v533 + 1163531501, 20);
            v538 = v537 + __ROL4__((v535 & v537) + (v536 & ~v535) + v1057 + v534 - 1444681467, 5);
            v539 = v538 + __ROL4__((v536 & v538) + (v537 & ~v536) + v1047 + v535 - 51403784, 9);
            v540 = v539 + __ROL4__((v537 & v539) + (v538 & ~v537) + v1051 + v536 + 1735328473, 14);
            v541 = v540 + __ROL4__((v538 & v540) + (v539 & ~v538) + v1056 + v537 - 1926607734, 20);
            v542 = v541 + __ROL4__((v539 ^ v540 ^ v541) + v1049 + v538 - 378558, 4);
            v543 = v542 + __ROL4__((v542 ^ v540 ^ v541) + v1052 + v539 - 2022574463, 11);
            v544 = v543 + __ROL4__((v541 ^ v542 ^ v543) + v1055 + v540 + 1839030562, 16);
            v545 = v544 + __ROL4__((v544 ^ v542 ^ v543) + v1058 + v541 - 35309556, 23);
            v546 = v545 + __ROL4__((v543 ^ v544 ^ v545) + HIDWORD(v1046) + v542 - 1530992060, 4);
            v547 = v546 + __ROL4__((v546 ^ v544 ^ v545) + v1048 + v543 + 1272893353, 11);
            v548 = v547 + __ROL4__(v1051 + v544 + (v545 ^ v546 ^ v547) - 155497632, 16);
            v549 = v548 + __ROL4__((v548 ^ v546 ^ v547) + v1054 + v545 - 1094730640, 23);
            v550 = v549 + __ROL4__((v549 ^ v547 ^ v548) + v1057 + v546 + 681279174, 4);
            v551 = v550 + __ROL4__((v550 ^ v548 ^ v549) + (_DWORD)v1046 + v547 - 358537222, 11);
            v552 = v551 + __ROL4__((v551 ^ v549 ^ v550) + HIDWORD(v1047) + v548 - 722521979, 16);
            v553 = v552 + __ROL4__((v552 ^ v550 ^ v551) + v1050 + v549 + 76029189, 23);
            v554 = v553 + __ROL4__((v553 ^ v551 ^ v552) + v1053 + v550 - 640364487, 4);
            v555 = v554 + __ROL4__((v554 ^ v552 ^ v553) + v1056 + v551 - 421815835, 11);
            v556 = v555 + __ROL4__((v555 ^ v553 ^ v554) + v1059 + v552 + 530742520, 16);
            v557 = v556 + __ROL4__((v556 ^ v554 ^ v555) + v1047 + v553 - 995338651, 23);
            v558 = v557 + __ROL4__((v556 ^ (v557 | ~v555)) + (_DWORD)v1046 + v554 - 198630844, 6);
            v559 = v558 + __ROL4__((v557 ^ (v558 | ~v556)) + v1051 + v555 + 1126891415, 10);
            v560 = v559 + __ROL4__((v558 ^ (v559 | ~v557)) + v1058 + v556 - 1416354905, 15);
            v561 = v560 + __ROL4__((v559 ^ (v560 | ~v558)) + v1049 + v557 - 57434055, 21);
            v562 = v561 + __ROL4__((v560 ^ (v561 | ~v559)) + v1056 + v558 + 1700485571, 6);
            v563 = v562 + __ROL4__(HIDWORD(v1047) + v559 + (v561 ^ (v562 | ~v560)) - 1894986606, 10);
            v564 = v563 + __ROL4__((v562 ^ (~(v563 ^ v561) | v563 & ~v561)) + v1054 + v560 - 1051523, 15);
            v565 = v564 + __ROL4__(HIDWORD(v1046) + v561 + (v563 ^ (v564 | ~v562)) - 2054922799, 21);
            v566 = v565 + __ROL4__((v564 ^ (v565 | ~v563)) + v1052 + v562 + 1873313359, 6);
            v567 = v566 + __ROL4__((v565 ^ (v566 | ~v564)) + v1059 + v563 - 30611744, 10);
            v568 = v567 + __ROL4__((v566 ^ (~(v567 ^ v565) | v567 & ~v565)) + v1050 + v564 - 1560198380, 15);
            v569 = v568 + __ROL4__(v1057 + v565 + (v567 ^ (~(v566 ^ v568) | v568 & ~v566)) + 1309151649, 21);
            v570 = v569 + __ROL4__(v1048 + v566 + (v568 ^ (v569 | ~v567)) - 145523070, 6);
            v571 = v570 + __ROL4__((v569 ^ (~(v570 ^ v568) | v570 & ~v568)) + v1055 + v567 - 1120210379, 10);
            v572 = v571 + __ROL4__(v1047 + v568 + (v570 ^ (v571 | ~v569)) + 718787259, 15);
            LODWORD(v1061[0]) = v992 + v570;
            HIDWORD(v1061[0]) = __ROL4__((v571 ^ (v572 | ~v570)) + v1053 + v569 - 343485551, 21) + v572 + v503;
            LODWORD(v1061[1]) = v998 + v572;
            HIDWORD(v1061[1]) = v1007 + v571;
            v573 = 0;
LABEL_485:
            v574 = 976919488;
            while ( 1 )
            {
              while ( v574 <= -587301062 )
              {
                if ( v574 == -1016511951 )
                {
                  v573 = (unsigned int)v1060;
                  goto LABEL_485;
                }
                *((_BYTE *)&v1046 + (int)v968) = 0;
                v574 = -455638576;
              }
              if ( v574 == -587301061 )
                break;
              if ( v574 == -455638576 )
              {
                LODWORD(v1060) = (_DWORD)v968 + 1;
                v574 = -1016511951;
              }
              else
              {
                LODWORD(v968) = v573;
                v574 = -587301061;
                if ( v573 < 0x40 )
                  v574 = -588599311;
              }
            }
            i17 = 848251583;
            v489 = v973;
          }
          if ( i17 != 1916821574 )
            break;
          v491 = &v1011[(unsigned int)v989];
          v492 = *(_DWORD *)v975;
          v493 = *((_DWORD *)v975 + 1);
          v494 = *((_DWORD *)v975 + 2);
          v495 = *((_DWORD *)v975 + 3);
          v496 = 0;
          v497 = 0;
LABEL_437:
          for ( i21 = 496118048; ; i21 = -673330124 )
          {
            while ( i21 > -942669484 )
            {
              if ( i21 == -942669483 )
              {
                LODWORD(v967) = (unsigned __int8)v491[(unsigned int)v1060]
                              | ((unsigned __int8)v491[(_DWORD)v1060 + 1] << 8);
                LODWORD(v966) = (_DWORD)v1060 + 2;
                i21 = -2007397661;
              }
              else
              {
                if ( i21 == -673330124 )
                {
                  v499 = (unsigned __int8)v491[(_DWORD)v1060 + 3] << 24;
                  *((_DWORD *)&v1046 + (unsigned int)v968) = v499 & (unsigned int)v967
                                                           | ((unsigned int)v967 | ((unsigned __int8)v974 << 16)) ^ v499;
                  v497 = (_DWORD)v968 + 1;
                  v496 = (_DWORD)v1060 + 4;
                  goto LABEL_437;
                }
                LODWORD(v1060) = v496;
                LODWORD(v968) = v497;
                i21 = -1614485789;
                if ( v496 < 0x40 )
                  i21 = -942669483;
              }
            }
            if ( i21 != -2007397661 )
              break;
            LOBYTE(v974) = v491[(unsigned int)v966];
          }
          v575 = v493 + __ROL4__((_DWORD)v1046 + (v495 & ~v493) + v492 + (v493 & v494) - 680876936, 7);
          v576 = v575 + __ROL4__((v493 & v575) + HIDWORD(v1046) + v495 + (v494 & ~v575) - 389564586, 12);
          v577 = v576 + __ROL4__((v575 & v576) + v494 + v1047 + (v493 & ~v576) + 606105819, 17);
          v578 = v577 + __ROL4__((v576 & v577) + v493 + HIDWORD(v1047) + (v575 & ~v577) - 1044525330, 22);
          v579 = v578 + __ROL4__((v577 & v578) + (v576 & ~v578) + v1048 + v575 - 176418897, 7);
          v580 = v579 + __ROL4__((v578 & v579) + (v577 & ~v579) + v1049 + v576 + 1200080426, 12);
          v581 = v580 + __ROL4__((v579 & v580) + (v578 & ~v580) + v1050 + v577 - 1473231341, 17);
          v582 = v581 + __ROL4__((v580 & v581) + (v579 & ~v581) + v1051 + v578 - 45705983, 22);
          v583 = v582 + __ROL4__((v580 & ~v582) + v1052 + v579 + (v581 & v582) + 1770035416, 7);
          v584 = v583 + __ROL4__((v582 & v583) + (v581 & ~v583) + v1053 + v580 - 1958414417, 12);
          v585 = v584 + __ROL4__((v583 & v584) + (v582 & ~v584) + v1054 + v581 - 42063, 17);
          LODWORD(v1008) = v494;
          v586 = v585 + __ROL4__((v584 & v585) + (v583 & ~v585) + v1055 + v582 - 1990404162, 22);
          v1007 = v495;
          v587 = v586 + __ROL4__((v584 & ~v586) + v1056 + v583 + (v585 & v586) + 1804603682, 7);
          v999 = v492;
          v588 = v587 + __ROL4__((v586 & v587) + (v585 & ~v587) + v1057 + v584 - 40341101, 12);
          v589 = v588 + __ROL4__((v587 & v588) + (~v588 & v586) + v1058 + v585 - 1502002290, 17);
          v590 = v589 + __ROL4__((v588 & v589) + (~v589 & v587) + v1059 + v586 + 1236535329, 22);
          v591 = v590 + __ROL4__((v588 & v590) + v587 + HIDWORD(v1046) + (v589 & ~v588) - 165796510, 5);
          v592 = v591 + __ROL4__((v589 & v591) + (v590 & ~v589) + v1050 + v588 - 1069501632, 9);
          v593 = v592 + __ROL4__((v591 & ~v590) + v1055 + v589 + (v590 & v592) + 643717713, 14);
          v594 = v593 + __ROL4__((v591 & v593) + (v592 & ~v591) + (_DWORD)v1046 + v590 - 373897302, 20);
          v595 = v594 + __ROL4__((v592 & v594) + (v593 & ~v592) + v1049 + v591 - 701558691, 5);
          v596 = v595 + __ROL4__((v593 & v595) + (v594 & ~v593) + v1054 + v592 + 38016083, 9);
          v597 = v596 + __ROL4__((v594 & v596) + (v595 & ~v594) + v1059 + v593 - 660478335, 14);
          v598 = v597 + __ROL4__((v595 & v597) + (v596 & ~v595) + v1048 + v594 - 405537848, 20);
          v599 = v598 + __ROL4__((v596 & v598) + (v597 & ~v596) + v1053 + v595 + 568446438, 5);
          v600 = v599 + __ROL4__((v597 & v599) + (v598 & ~v597) + v1058 + v596 - 1019803690, 9);
          v601 = v600 + __ROL4__((v598 & v600) + (v599 & ~v598) + HIDWORD(v1047) + v597 - 187363961, 14);
          v602 = v601 + __ROL4__((v599 & v601) + (v600 & ~v599) + v1052 + v598 + 1163531501, 20);
          v603 = v602 + __ROL4__((v600 & v602) + (v601 & ~v600) + v1057 + v599 - 1444681467, 5);
          v604 = v603 + __ROL4__((v601 & v603) + (v602 & ~v601) + v1047 + v600 - 51403784, 9);
          v605 = v604 + __ROL4__((v602 & v604) + (v603 & ~v602) + v1051 + v601 + 1735328473, 14);
          v606 = v605 + __ROL4__((v603 & v605) + (v604 & ~v603) + v1056 + v602 - 1926607734, 20);
          v607 = v606 + __ROL4__((v604 ^ v605 ^ v606) + v603 + v1049 - 378558, 4);
          v608 = v607 + __ROL4__((v607 ^ v605 ^ v606) + v1052 + v604 - 2022574463, 11);
          v609 = v608 + __ROL4__((v606 ^ v607 ^ v608) + v1055 + v605 + 1839030562, 16);
          v610 = v609 + __ROL4__((v609 ^ v607 ^ v608) + v1058 + v606 - 35309556, 23);
          v611 = v610 + __ROL4__((v608 ^ v609 ^ v610) + HIDWORD(v1046) + v607 - 1530992060, 4);
          v612 = v611 + __ROL4__((v611 ^ v609 ^ v610) + v1048 + v608 + 1272893353, 11);
          v613 = v612 + __ROL4__(v1051 + v609 + (v610 ^ v611 ^ v612) - 155497632, 16);
          v614 = v613 + __ROL4__((v613 ^ v611 ^ v612) + v1054 + v610 - 1094730640, 23);
          v615 = v614 + __ROL4__((v614 ^ v612 ^ v613) + v1057 + v611 + 681279174, 4);
          v616 = v615 + __ROL4__((v615 ^ v613 ^ v614) + (_DWORD)v1046 + v612 - 358537222, 11);
          v617 = v616 + __ROL4__((v616 ^ v614 ^ v615) + HIDWORD(v1047) + v613 - 722521979, 16);
          v618 = v617 + __ROL4__((v617 ^ v615 ^ v616) + v1050 + v614 + 76029189, 23);
          v619 = v618 + __ROL4__((v618 ^ v616 ^ v617) + v1053 + v615 - 640364487, 4);
          v620 = v619 + __ROL4__((v619 ^ v617 ^ v618) + v1056 + v616 - 421815835, 11);
          v621 = v620 + __ROL4__((v620 ^ v618 ^ v619) + v1059 + v617 + 530742520, 16);
          v622 = v621 + __ROL4__((v621 ^ v619 ^ v620) + v1047 + v618 - 995338651, 23);
          v623 = v622 + __ROL4__((v621 ^ (v622 | ~v620)) + (_DWORD)v1046 + v619 - 198630844, 6);
          v624 = v623 + __ROL4__((v622 ^ (v623 | ~v621)) + v1051 + v620 + 1126891415, 10);
          v625 = v624 + __ROL4__((v623 ^ (v624 | ~v622)) + v1058 + v621 - 1416354905, 15);
          v626 = v625 + __ROL4__((v624 ^ (v625 | ~v623)) + v1049 + v622 - 57434055, 21);
          v627 = v626 + __ROL4__(v1056 + v623 + (v625 ^ (v626 | ~v624)) + 1700485571, 6);
          v628 = v627 + __ROL4__((v626 ^ (v627 | ~v625)) + HIDWORD(v1047) + v624 - 1894986606, 10);
          v629 = v628 + __ROL4__((v627 ^ (~(v628 ^ v626) | v628 & ~v626)) + v1054 + v625 - 1051523, 15);
          v630 = v629 + __ROL4__((v628 ^ (v629 | ~v627)) + HIDWORD(v1046) + v626 - 2054922799, 21);
          v631 = v630 + __ROL4__((v629 ^ (v630 | ~v628)) + v1052 + v627 + 1873313359, 6);
          v632 = v631 + __ROL4__(v1059 + v628 + (v630 ^ (v631 | ~v629)) - 30611744, 10);
          v633 = v632 + __ROL4__((v631 ^ (~(v632 ^ v630) | v632 & ~v630)) + v1050 + v629 - 1560198380, 15);
          v634 = v633 + __ROL4__((v632 ^ (~(v631 ^ v633) | v633 & ~v631)) + v1057 + v630 + 1309151649, 21);
          v635 = v634 + __ROL4__(v1048 + v631 + (v633 ^ (v634 | ~v632)) - 145523070, 6);
          v636 = v635 + __ROL4__((v634 ^ (~(v635 ^ v633) | v635 & ~v633)) + v1055 + v632 - 1120210379, 10);
          v637 = v636 + __ROL4__(v1047 + v633 + (v635 ^ (v636 | ~v634)) + 718787259, 15);
          v638 = (v636 ^ (v637 | ~v635)) + v1053 + v634 - 343485551;
          *(_DWORD *)v975 = v999 + v635;
          *((_DWORD *)v975 + 1) = __ROL4__(v638, 21) + v637 + v493;
          *((_DWORD *)v975 + 2) = (_DWORD)v1008 + v637;
          *((_DWORD *)v975 + 3) = v1007 + v636;
          v639 = 0;
LABEL_497:
          v640 = 976919488;
          while ( 1 )
          {
            while ( v640 <= -587301062 )
            {
              if ( v640 == -1016511951 )
              {
                v639 = (unsigned int)v1060;
                goto LABEL_497;
              }
              *((_BYTE *)&v1046 + (int)v968) = 0;
              v640 = -455638576;
            }
            if ( v640 == -587301061 )
              break;
            if ( v640 == -455638576 )
            {
              LODWORD(v1060) = (_DWORD)v968 + 1;
              v640 = -1016511951;
            }
            else
            {
              LODWORD(v968) = v639;
              v640 = -587301061;
              if ( v639 < 0x40 )
                v640 = -588599311;
            }
          }
          v489 = (_DWORD)v989 + 64;
        }
        v987 = v986 - (_DWORD)v1013;
        for ( i22 = 0; ; i22 = (_DWORD)v968 + 1 )
        {
          for ( i23 = -1785266232; ; i23 = -1827872406 )
          {
            while ( i23 <= -1207850492 )
            {
              if ( i23 == -1827872406 )
              {
                *((_BYTE *)v1046 + (_QWORD)&v1062[1] + (unsigned int)v1012) = *((_BYTE *)v1046
                                                                              + (unsigned int)v1013
                                                                              + (_QWORD)v1011);
                i23 = 976403079;
              }
              else
              {
                LODWORD(v968) = i22;
                i23 = -554264179;
                if ( i22 < v987 )
                  i23 = -1207850491;
              }
            }
            if ( i23 != -1207850491 )
              break;
            v1046 = (void *)(int)v968;
          }
          if ( i23 == -554264179 )
            break;
        }
        v968 = (unsigned int *)ptr;
        v643 = 0;
        v644 = 0;
LABEL_522:
        for ( i24 = -1717192363; ; i24 = -2031488434 )
        {
          while ( 1 )
          {
            while ( i24 <= -736119120 )
            {
              if ( i24 == -2031488434 )
              {
                *((_BYTE *)&v1061[-1] + (unsigned int)v980) = (_BYTE)v966;
                v644 = (_DWORD)v975 + 1;
                v643 = (_DWORD)v971 + 4;
                goto LABEL_522;
              }
              LODWORD(v971) = v643;
              LODWORD(v975) = v644;
              i24 = 494299060;
              if ( v643 < 8 )
                i24 = -736119119;
            }
            if ( i24 != -736119119 )
              break;
            v1046 = (char *)v1062 + 4 * (unsigned int)v975;
            *((_BYTE *)&v1061[-1] + (unsigned int)v971) = *(_BYTE *)v1046;
            *((_BYTE *)&v1061[-1] + (unsigned int)((_DWORD)v971 + 1)) = *((_BYTE *)v1046 + 1);
            *((_BYTE *)&v1061[-1] + (unsigned int)((_DWORD)v971 + 2)) = *((_BYTE *)v1046 + 2);
            i24 = 1223234202;
          }
          if ( i24 == 494299060 )
            break;
          LOBYTE(v966) = *((_BYTE *)v1046 + 3);
          LODWORD(v980) = (_DWORD)v971 + 3;
        }
        v646 = ((((LODWORD(v1062[0]) >> 3) & 0x3F) >= 0x38) << 6) - ((LODWORD(v1062[0]) >> 3) & 0x3F);
        v1005 = v1062[0];
        v988 = v646 + 56;
        v1016 = (unsigned int)(v646 + 56) >> 29;
        v647 = 8 * v646 + 448;
        v1020 = v647;
        for ( i25 = -544619405; ; i25 = 848251583 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( i25 <= 848251582 )
              {
                if ( i25 <= -544619406 )
                {
                  if ( i25 == -2109407181 )
                  {
                    i25 = 1843554541;
                    LODWORD(v1011) = 0;
                    LODWORD(v1013) = v974;
                  }
                  else
                  {
                    i25 = 1843554541;
                    LODWORD(v1013) = 0;
                    LODWORD(v1011) = v1033;
                  }
                }
                else if ( i25 == -544619405 )
                {
                  v974 = (v1005 >> 3) & 0x3F;
                  i25 = -165828501;
                }
                else if ( i25 == -316297161 )
                {
                  ++HIDWORD(v1062[0]);
                  i25 = 1066382172;
                }
                else
                {
                  LODWORD(v1062[0]) = v1020 + v1005;
                  i25 = 1066382172;
                  if ( __CFADD__(v1020, v1005) )
                    i25 = -316297161;
                }
              }
              if ( i25 > 1114565259 )
                break;
              if ( i25 == 848251583 )
              {
                v1033 = v647;
                i25 = -785424894;
                if ( v647 + 63 < v988 )
                  i25 = 1916821574;
              }
              else
              {
                HIDWORD(v1062[0]) += v1016;
                v977 = 64 - v974;
                i25 = 1114565260;
                if ( 64 - v974 > v988 )
                  i25 = -2109407181;
              }
            }
            if ( i25 != 1114565260 )
              break;
            for ( i26 = 0; ; i26 = (_DWORD)v966 + 1 )
            {
              for ( i27 = -1785266232; ; i27 = -1827872406 )
              {
                while ( i27 <= -1207850492 )
                {
                  if ( i27 == -1827872406 )
                  {
                    *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v974) = *((_BYTE *)&unk_D407C0 + (_QWORD)v1046);
                    i27 = 976403079;
                  }
                  else
                  {
                    LODWORD(v966) = i26;
                    i27 = -554264179;
                    if ( i26 < v977 )
                      i27 = -1207850491;
                  }
                }
                if ( i27 != -1207850491 )
                  break;
                v1046 = (void *)(int)v966;
              }
              if ( i27 == -554264179 )
                break;
            }
            v975 = v1061;
            v659 = (unsigned int)v1061[0];
            v660 = HIDWORD(v1061[0]);
            v661 = (int)v1061[1];
            v1008 = v1061;
            v662 = HIDWORD(v1061[1]);
            v663 = 0;
            v664 = 0;
LABEL_582:
            for ( i28 = 496118048; ; i28 = -673330124 )
            {
              while ( i28 > -942669484 )
              {
                if ( i28 == -942669483 )
                {
                  v973 = *((unsigned __int8 *)&v1062[1] + (unsigned int)v967)
                       | (*((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 1)) << 8);
                  LODWORD(v989) = (_DWORD)v967 + 2;
                  i28 = -2007397661;
                }
                else
                {
                  if ( i28 == -673330124 )
                  {
                    v666 = *((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 3)) << 24;
                    *((_DWORD *)&v1046 + (unsigned int)v966) = v666 & v973 | (v973 | (v965 << 16)) ^ v666;
                    v664 = (_DWORD)v966 + 1;
                    v663 = (_DWORD)v967 + 4;
                    goto LABEL_582;
                  }
                  LODWORD(v967) = v663;
                  LODWORD(v966) = v664;
                  i28 = -1614485789;
                  if ( v663 < 0x40 )
                    i28 = -942669483;
                }
              }
              if ( i28 != -2007397661 )
                break;
              v965 = *((_BYTE *)&v1062[1] + (unsigned int)v989);
            }
            v667 = v660 + __ROL4__((_DWORD)v1046 + (v662 & ~v660) + v659 + (v660 & v661) - 680876936, 7);
            v668 = v667 + __ROL4__(HIDWORD(v1046) + v662 + (v661 & ~v667) + (v660 & v667) - 389564586, 12);
            v669 = v660;
            v1000 = v660;
            v983 = v662;
            v670 = v668 + __ROL4__((v667 & v668) + v1047 + v661 + (v660 & ~v668) + 606105819, 17);
            v671 = v670 + __ROL4__((v668 & v670) + HIDWORD(v1047) + v669 + (v667 & ~v670) - 1044525330, 22);
            v672 = v671 + __ROL4__((v670 & v671) + (v668 & ~v671) + v1048 + v667 - 176418897, 7);
            v673 = v672 + __ROL4__((v671 & v672) + (v670 & ~v672) + v1049 + v668 + 1200080426, 12);
            v674 = v673 + __ROL4__((v672 & v673) + (v671 & ~v673) + v1050 + v670 - 1473231341, 17);
            v675 = v674 + __ROL4__((v673 & v674) + (v672 & ~v674) + v1051 + v671 - 45705983, 22);
            v676 = v675 + __ROL4__((v673 & ~v675) + v1052 + v672 + (v674 & v675) + 1770035416, 7);
            v677 = v676 + __ROL4__((v675 & v676) + (v674 & ~v676) + v1053 + v673 - 1958414417, 12);
            LODWORD(v1012) = v661;
            v678 = v677 + __ROL4__((v676 & v677) + (v675 & ~v677) + v1054 + v674 - 42063, 17);
            v679 = v678 + __ROL4__((v677 & v678) + (v676 & ~v678) + v1055 + v675 - 1990404162, 22);
            v680 = v679 + __ROL4__((v678 & v679) + (v677 & ~v679) + v1056 + v676 + 1804603682, 7);
            v681 = v680 + __ROL4__((v678 & ~v680) + v1057 + v677 + (v679 & v680) - 40341101, 12);
            v1007 = v659;
            v682 = v681 + __ROL4__((v680 & v681) + (~v681 & v679) + v1058 + v678 - 1502002290, 17);
            v683 = HIDWORD(v1046) + v680;
            v684 = v682 + __ROL4__((~v682 & v680) + v1059 + v679 + (v681 & v682) + 1236535329, 22);
            v685 = v684 + __ROL4__((v681 & v684) + v683 + (v682 & ~v681) - 165796510, 5);
            v686 = v685 + __ROL4__((v682 & v685) + (v684 & ~v682) + v1050 + v681 - 1069501632, 9);
            v687 = v686 + __ROL4__((v684 & v686) + (v685 & ~v684) + v1055 + v682 + 643717713, 14);
            v688 = v687 + __ROL4__((v685 & v687) + (v686 & ~v685) + (_DWORD)v1046 + v684 - 373897302, 20);
            v689 = v688 + __ROL4__((v686 & v688) + (v687 & ~v686) + v1049 + v685 - 701558691, 5);
            v690 = v689 + __ROL4__((v687 & v689) + (v688 & ~v687) + v1054 + v686 + 38016083, 9);
            v691 = v690 + __ROL4__((v688 & v690) + (v689 & ~v688) + v1059 + v687 - 660478335, 14);
            v692 = v691 + __ROL4__((v689 & v691) + (v690 & ~v689) + v1048 + v688 - 405537848, 20);
            v693 = v692 + __ROL4__((v690 & v692) + (v691 & ~v690) + v1053 + v689 + 568446438, 5);
            v694 = v693 + __ROL4__((v691 & v693) + (v692 & ~v691) + v1058 + v690 - 1019803690, 9);
            v695 = v694 + __ROL4__((v692 & v694) + (v693 & ~v692) + HIDWORD(v1047) + v691 - 187363961, 14);
            v696 = v695 + __ROL4__((v694 & ~v693) + v1052 + v692 + (v693 & v695) + 1163531501, 20);
            v697 = v696 + __ROL4__((v694 & v696) + (v695 & ~v694) + v1057 + v693 - 1444681467, 5);
            v698 = v697 + __ROL4__((v695 & v697) + (v696 & ~v695) + v1047 + v694 - 51403784, 9);
            v699 = v698 + __ROL4__((v696 & v698) + (v697 & ~v696) + v1051 + v695 + 1735328473, 14);
            v700 = v699 + __ROL4__((v697 & v699) + (v698 & ~v697) + v1056 + v696 - 1926607734, 20);
            v701 = v700 + __ROL4__((v698 ^ v699 ^ v700) + v1049 + v697 - 378558, 4);
            v702 = v701 + __ROL4__(v1052 + v698 + (v701 ^ v699 ^ v700) - 2022574463, 11);
            v703 = v702 + __ROL4__((v700 ^ v701 ^ v702) + v1055 + v699 + 1839030562, 16);
            v704 = v703 + __ROL4__((v703 ^ v701 ^ v702) + v1058 + v700 - 35309556, 23);
            v705 = v704 + __ROL4__((v702 ^ v703 ^ v704) + HIDWORD(v1046) + v701 - 1530992060, 4);
            v706 = v705 + __ROL4__((v705 ^ v703 ^ v704) + v1048 + v702 + 1272893353, 11);
            v707 = v706 + __ROL4__((v704 ^ v705 ^ v706) + v1051 + v703 - 155497632, 16);
            v708 = v707 + __ROL4__((v707 ^ v705 ^ v706) + v1054 + v704 - 1094730640, 23);
            v709 = v708 + __ROL4__(v1057 + v705 + (v706 ^ v707 ^ v708) + 681279174, 4);
            v710 = v709 + __ROL4__((v709 ^ v707 ^ v708) + (_DWORD)v1046 + v706 - 358537222, 11);
            v711 = v710 + __ROL4__((v710 ^ v708 ^ v709) + HIDWORD(v1047) + v707 - 722521979, 16);
            v712 = v711 + __ROL4__((v711 ^ v709 ^ v710) + v1050 + v708 + 76029189, 23);
            v713 = v712 + __ROL4__((v712 ^ v710 ^ v711) + v1053 + v709 - 640364487, 4);
            v714 = v713 + __ROL4__(v1056 + v710 + (v713 ^ v711 ^ v712) - 421815835, 11);
            v715 = v714 + __ROL4__((v714 ^ v712 ^ v713) + v1059 + v711 + 530742520, 16);
            v716 = v715 + __ROL4__((v715 ^ v713 ^ v714) + v1047 + v712 - 995338651, 23);
            v717 = v716 + __ROL4__((v715 ^ (v716 | ~v714)) + (_DWORD)v1046 + v713 - 198630844, 6);
            v718 = v717 + __ROL4__((v716 ^ (v717 | ~v715)) + v1051 + v714 + 1126891415, 10);
            v719 = v718 + __ROL4__((v717 ^ (v718 | ~v716)) + v1058 + v715 - 1416354905, 15);
            v720 = v719 + __ROL4__(v1049 + v716 + (v718 ^ (v719 | ~v717)) - 57434055, 21);
            v721 = v720 + __ROL4__((v719 ^ (v720 | ~v718)) + v1056 + v717 + 1700485571, 6);
            v722 = v721 + __ROL4__((v720 ^ (v721 | ~v719)) + HIDWORD(v1047) + v718 - 1894986606, 10);
            v723 = v722 + __ROL4__((v721 ^ (~(v722 ^ v720) | v722 & ~v720)) + v1054 + v719 - 1051523, 15);
            v724 = v723 + __ROL4__((v722 ^ (v723 | ~v721)) + HIDWORD(v1046) + v720 - 2054922799, 21);
            v725 = v724 + __ROL4__((v723 ^ (v724 | ~v722)) + v1052 + v721 + 1873313359, 6);
            v726 = v725 + __ROL4__(v1059 + v722 + (v724 ^ (v725 | ~v723)) - 30611744, 10);
            v727 = v726 + __ROL4__((v725 ^ (~(v726 ^ v724) | v726 & ~v724)) + v1050 + v723 - 1560198380, 15);
            v728 = v727 + __ROL4__((v726 ^ (~(v725 ^ v727) | v727 & ~v725)) + v1057 + v724 + 1309151649, 21);
            v729 = v728 + __ROL4__(v1048 + v725 + (v727 ^ (v728 | ~v726)) - 145523070, 6);
            v730 = v729 + __ROL4__((v728 ^ (~(v729 ^ v727) | v729 & ~v727)) + v1055 + v726 - 1120210379, 10);
            v731 = v730 + __ROL4__(v1047 + v727 + (v729 ^ (v730 | ~v728)) + 718787259, 15);
            LODWORD(v1061[0]) = v1007 + v729;
            HIDWORD(v1061[0]) = __ROL4__((v730 ^ (v731 | ~v729)) + v1053 + v728 - 343485551, 21) + v731 + v1000;
            LODWORD(v1061[1]) = v1012 + v731;
            HIDWORD(v1061[1]) = v983 + v730;
            v732 = 0;
LABEL_594:
            v733 = 976919488;
            while ( 1 )
            {
              while ( v733 <= -587301062 )
              {
                if ( v733 == -1016511951 )
                {
                  v732 = (unsigned int)v967;
                  goto LABEL_594;
                }
                *((_BYTE *)&v1046 + (int)v966) = 0;
                v733 = -455638576;
              }
              if ( v733 == -587301061 )
                break;
              if ( v733 == -455638576 )
              {
                LODWORD(v967) = (_DWORD)v966 + 1;
                v733 = -1016511951;
              }
              else
              {
                LODWORD(v966) = v732;
                v733 = -587301061;
                if ( v732 < 0x40 )
                  v733 = -588599311;
              }
            }
            i25 = 848251583;
            v647 = v977;
          }
          if ( i25 != 1916821574 )
            break;
          v649 = *(_DWORD *)v975;
          v650 = *((_DWORD *)v975 + 1);
          v651 = *((_DWORD *)v975 + 2);
          LODWORD(v1012) = (_DWORD)v975;
          v652 = *((_DWORD *)v975 + 3);
          v653 = 0;
          v654 = 0;
LABEL_545:
          for ( i29 = 496118048; ; i29 = -673330124 )
          {
            while ( i29 > -942669484 )
            {
              if ( i29 == -942669483 )
              {
                v973 = *((unsigned __int8 *)&unk_D407C0 + v1033 + (unsigned __int64)(unsigned int)v967)
                     | (*((unsigned __int8 *)&unk_D407C0 + v1033 + (unsigned __int64)(unsigned int)((_DWORD)v967 + 1)) << 8);
                LODWORD(v989) = (_DWORD)v967 + 2;
                i29 = -2007397661;
              }
              else
              {
                if ( i29 == -673330124 )
                {
                  v656 = *((unsigned __int8 *)&unk_D407C0 + v1033 + (unsigned __int64)(unsigned int)((_DWORD)v967 + 3)) << 24;
                  *((_DWORD *)&v1046 + (unsigned int)v966) = v656 & v973 | (v973 | (v965 << 16)) ^ v656;
                  v654 = (_DWORD)v966 + 1;
                  v653 = (_DWORD)v967 + 4;
                  goto LABEL_545;
                }
                LODWORD(v967) = v653;
                LODWORD(v966) = v654;
                i29 = -1614485789;
                if ( v653 < 0x40 )
                  i29 = -942669483;
              }
            }
            if ( i29 != -2007397661 )
              break;
            v965 = *((_BYTE *)&unk_D407C0 + v1033 + (unsigned __int64)(unsigned int)v989);
          }
          v734 = v650 + __ROL4__((_DWORD)v1046 + (v652 & ~v650) + v649 + (v650 & v651) - 680876936, 7);
          v735 = v734 + __ROL4__((v650 & v734) + HIDWORD(v1046) + v652 + (v651 & ~v734) - 389564586, 12);
          LODWORD(v1008) = v650;
          v736 = v735 + __ROL4__((v734 & v735) + v651 + v1047 + (v650 & ~v735) + 606105819, 17);
          v737 = v736 + __ROL4__((v735 & v736) + v650 + HIDWORD(v1047) + (v734 & ~v736) - 1044525330, 22);
          v738 = v737 + __ROL4__((v736 & v737) + (v735 & ~v737) + v1048 + v734 - 176418897, 7);
          v739 = v738 + __ROL4__((v737 & v738) + (v736 & ~v738) + v1049 + v735 + 1200080426, 12);
          v740 = v739 + __ROL4__((v738 & v739) + (v737 & ~v739) + v1050 + v736 - 1473231341, 17);
          v741 = v740 + __ROL4__((v739 & v740) + (v738 & ~v740) + v1051 + v737 - 45705983, 22);
          v742 = v741 + __ROL4__((v740 & v741) + (v739 & ~v741) + v1052 + v738 + 1770035416, 7);
          v743 = v742 + __ROL4__((v741 & v742) + (v740 & ~v742) + v1053 + v739 - 1958414417, 12);
          v744 = v743 + __ROL4__((v741 & ~v743) + v1054 + v740 + (v742 & v743) - 42063, 17);
          v1007 = v651;
          v745 = v744 + __ROL4__((v743 & v744) + (v742 & ~v744) + v1055 + v741 - 1990404162, 22);
          v746 = v745 + __ROL4__((v744 & v745) + (v743 & ~v745) + v1056 + v742 + 1804603682, 7);
          v747 = v746 + __ROL4__((v745 & v746) + (v744 & ~v746) + v1057 + v743 - 40341101, 12);
          v1001 = v652;
          v748 = v747 + __ROL4__((v746 & v747) + (~v747 & v745) + v1058 + v744 - 1502002290, 17);
          v993 = v649;
          v749 = v748 + __ROL4__((v747 & v748) + (~v748 & v746) + v1059 + v745 + 1236535329, 22);
          v750 = v749 + __ROL4__(HIDWORD(v1046) + v746 + (v748 & ~v747) + (v747 & v749) - 165796510, 5);
          v751 = v750 + __ROL4__((v748 & v750) + (v749 & ~v748) + v1050 + v747 - 1069501632, 9);
          v752 = v751 + __ROL4__((v750 & ~v749) + v1055 + v748 + (v749 & v751) + 643717713, 14);
          v753 = v752 + __ROL4__((v750 & v752) + (v751 & ~v750) + (_DWORD)v1046 + v749 - 373897302, 20);
          v754 = v753 + __ROL4__((v751 & v753) + (v752 & ~v751) + v1049 + v750 - 701558691, 5);
          v755 = v754 + __ROL4__((v752 & v754) + (v753 & ~v752) + v1054 + v751 + 38016083, 9);
          v756 = v755 + __ROL4__((v753 & v755) + (v754 & ~v753) + v1059 + v752 - 660478335, 14);
          v757 = v756 + __ROL4__((v754 & v756) + (v755 & ~v754) + v1048 + v753 - 405537848, 20);
          v758 = v757 + __ROL4__((v755 & v757) + (v756 & ~v755) + v1053 + v754 + 568446438, 5);
          v759 = v758 + __ROL4__((v756 & v758) + (v757 & ~v756) + v1058 + v755 - 1019803690, 9);
          v760 = v759 + __ROL4__((v757 & v759) + (v758 & ~v757) + HIDWORD(v1047) + v756 - 187363961, 14);
          v761 = v760 + __ROL4__((v758 & v760) + (v759 & ~v758) + v1052 + v757 + 1163531501, 20);
          v762 = v761 + __ROL4__((v759 & v761) + (v760 & ~v759) + v1057 + v758 - 1444681467, 5);
          v763 = v762 + __ROL4__((v760 & v762) + (v761 & ~v760) + v1047 + v759 - 51403784, 9);
          v764 = v763 + __ROL4__((v761 & v763) + (v762 & ~v761) + v1051 + v760 + 1735328473, 14);
          v765 = v764 + __ROL4__((v762 & v764) + (v763 & ~v762) + v1056 + v761 - 1926607734, 20);
          v766 = v765 + __ROL4__((v763 ^ v764 ^ v765) + v1049 + v762 - 378558, 4);
          v767 = v766 + __ROL4__(v1052 + v763 + (v766 ^ v764 ^ v765) - 2022574463, 11);
          v768 = v767 + __ROL4__(v1055 + v764 + (v765 ^ v766 ^ v767) + 1839030562, 16);
          v769 = v768 + __ROL4__((v768 ^ v766 ^ v767) + v1058 + v765 - 35309556, 23);
          v770 = v769 + __ROL4__((v767 ^ v768 ^ v769) + HIDWORD(v1046) + v766 - 1530992060, 4);
          v771 = v770 + __ROL4__((v770 ^ v768 ^ v769) + v1048 + v767 + 1272893353, 11);
          v772 = v771 + __ROL4__(v1051 + v768 + (v769 ^ v770 ^ v771) - 155497632, 16);
          v773 = v772 + __ROL4__((v772 ^ v770 ^ v771) + v1054 + v769 - 1094730640, 23);
          v774 = v773 + __ROL4__((v771 ^ v772 ^ v773) + v1057 + v770 + 681279174, 4);
          v775 = v774 + __ROL4__((v774 ^ v772 ^ v773) + (_DWORD)v1046 + v771 - 358537222, 11);
          v776 = v775 + __ROL4__(HIDWORD(v1047) + v772 + (v775 ^ v773 ^ v774) - 722521979, 16);
          v777 = v776 + __ROL4__((v776 ^ v774 ^ v775) + v1050 + v773 + 76029189, 23);
          v778 = v777 + __ROL4__((v777 ^ v775 ^ v776) + v1053 + v774 - 640364487, 4);
          v779 = v778 + __ROL4__((v778 ^ v776 ^ v777) + v1056 + v775 - 421815835, 11);
          v780 = v779 + __ROL4__((v779 ^ v777 ^ v778) + v1059 + v776 + 530742520, 16);
          v781 = v780 + __ROL4__((v780 ^ v778 ^ v779) + v1047 + v777 - 995338651, 23);
          v782 = v781 + __ROL4__((v780 ^ (v781 | ~v779)) + (_DWORD)v1046 + v778 - 198630844, 6);
          v783 = v782 + __ROL4__((v781 ^ (v782 | ~v780)) + v1051 + v779 + 1126891415, 10);
          v784 = v783 + __ROL4__((v782 ^ (v783 | ~v781)) + v1058 + v780 - 1416354905, 15);
          v785 = v784 + __ROL4__((v783 ^ (v784 | ~v782)) + v1049 + v781 - 57434055, 21);
          v786 = v785 + __ROL4__((v784 ^ (v785 | ~v783)) + v1056 + v782 + 1700485571, 6);
          v787 = v786 + __ROL4__((v785 ^ (v786 | ~v784)) + HIDWORD(v1047) + v783 - 1894986606, 10);
          v788 = v787 + __ROL4__((v786 ^ (~(v787 ^ v785) | v787 & ~v785)) + v1054 + v784 - 1051523, 15);
          v789 = v788 + __ROL4__((v787 ^ (v788 | ~v786)) + HIDWORD(v1046) + v785 - 2054922799, 21);
          v790 = v789 + __ROL4__((v788 ^ (v789 | ~v787)) + v1052 + v786 + 1873313359, 6);
          v791 = v790 + __ROL4__(v1059 + v787 + (v789 ^ (v790 | ~v788)) - 30611744, 10);
          v792 = v791 + __ROL4__((v790 ^ (~(v791 ^ v789) | v791 & ~v789)) + v1050 + v788 - 1560198380, 15);
          v793 = v792 + __ROL4__((v791 ^ (~(v790 ^ v792) | v792 & ~v790)) + v1057 + v789 + 1309151649, 21);
          v794 = v793 + __ROL4__(v1048 + v790 + (v792 ^ (v793 | ~v791)) - 145523070, 6);
          v795 = v794 + __ROL4__((v793 ^ (~(v794 ^ v792) | v794 & ~v792)) + v1055 + v791 - 1120210379, 10);
          v796 = v795 + __ROL4__(v1047 + v792 + (v794 ^ (v795 | ~v793)) + 718787259, 15);
          v797 = (v795 ^ (v796 | ~v794)) + v1053 + v793 - 343485551;
          *(_DWORD *)v975 = v993 + v794;
          *((_DWORD *)v975 + 1) = __ROL4__(v797, 21) + v796 + v650;
          *((_DWORD *)v975 + 2) = v1007 + v796;
          *((_DWORD *)v975 + 3) = v1001 + v795;
          v798 = 0;
LABEL_606:
          v799 = 976919488;
          while ( 1 )
          {
            while ( v799 <= -587301062 )
            {
              if ( v799 == -1016511951 )
              {
                v798 = (unsigned int)v967;
                goto LABEL_606;
              }
              *((_BYTE *)&v1046 + (int)v966) = 0;
              v799 = -455638576;
            }
            if ( v799 == -587301061 )
              break;
            if ( v799 == -455638576 )
            {
              LODWORD(v967) = (_DWORD)v966 + 1;
              v799 = -1016511951;
            }
            else
            {
              LODWORD(v966) = v798;
              v799 = -587301061;
              if ( v798 < 0x40 )
                v799 = -588599311;
            }
          }
          v647 = v1033 + 64;
        }
        LODWORD(v985) = v988 - (_DWORD)v1011;
        for ( i30 = 0; ; i30 = (_DWORD)v966 + 1 )
        {
          for ( i31 = -1785266232; ; i31 = -1827872406 )
          {
            while ( i31 <= -1207850492 )
            {
              if ( i31 == -1827872406 )
              {
                *((_BYTE *)v1046 + (_QWORD)&v1062[1] + (unsigned int)v1013) = *((_BYTE *)&unk_D407C0
                                                                              + (_QWORD)v1046
                                                                              + (unsigned int)v1011);
                i31 = 976403079;
              }
              else
              {
                LODWORD(v966) = i30;
                i31 = -554264179;
                if ( i30 < (unsigned int)v985 )
                  i31 = -1207850491;
              }
            }
            if ( i31 != -1207850491 )
              break;
            v1046 = (void *)(int)v966;
          }
          if ( i31 == -554264179 )
            break;
        }
        v978 = v1062;
        v972 = v1062;
        v802 = v1062[0];
        v1006 = v1062[0];
        for ( i32 = -544619405; ; i32 = 848251583 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( i32 <= 848251582 )
              {
                if ( i32 <= -544619406 )
                {
                  if ( i32 == -2109407181 )
                  {
                    i32 = 1843554541;
                    LODWORD(v1011) = 0;
                    LODWORD(v1013) = v974;
                  }
                  else
                  {
                    i32 = 1843554541;
                    LODWORD(v1013) = 0;
                    LODWORD(v1011) = v1033;
                  }
                }
                else if ( i32 == -544619405 )
                {
                  v974 = (v1006 >> 3) & 0x3F;
                  i32 = -165828501;
                }
                else if ( i32 == -316297161 )
                {
                  ++HIDWORD(v1062[0]);
                  i32 = 1066382172;
                }
                else
                {
                  LODWORD(v1062[0]) = v1006 + 64;
                  i32 = 1066382172;
                  if ( v1006 >= 0xFFFFFFC0 )
                    i32 = -316297161;
                }
              }
              if ( i32 > 1114565259 )
                break;
              if ( i32 == 848251583 )
              {
                v1033 = v802;
                i32 = -785424894;
                if ( v802 + 63 < 8 )
                  i32 = 1916821574;
              }
              else
              {
                v977 = 64 - v974;
                i32 = 1114565260;
                if ( 64 - v974 >= 9 )
                  i32 = -2109407181;
              }
            }
            if ( i32 != 1114565260 )
              break;
            for ( i33 = 0; ; i33 = (_DWORD)v966 + 1 )
            {
              for ( i34 = -1785266232; ; i34 = -1827872406 )
              {
                while ( i34 <= -1207850492 )
                {
                  if ( i34 == -1827872406 )
                  {
                    *((_BYTE *)v1046 + (_QWORD)&v1062[1] + v974) = *((_BYTE *)&v1061[-1] + (_QWORD)v1046);
                    i34 = 976403079;
                  }
                  else
                  {
                    LODWORD(v966) = i33;
                    i34 = -554264179;
                    if ( i33 < v977 )
                      i34 = -1207850491;
                  }
                }
                if ( i34 != -1207850491 )
                  break;
                v1046 = (void *)(int)v966;
              }
              if ( i34 == -554264179 )
                break;
            }
            v975 = v1061;
            v815 = (int)v1061[0];
            v816 = HIDWORD(v1061[0]);
            v817 = (int)v1061[1];
            v985 = v1061;
            v818 = HIDWORD(v1061[1]);
            v819 = 0;
            v820 = 0;
LABEL_679:
            for ( i35 = 496118048; ; i35 = -673330124 )
            {
              while ( i35 > -942669484 )
              {
                if ( i35 == -942669483 )
                {
                  v973 = *((unsigned __int8 *)&v1062[1] + (unsigned int)v967)
                       | (*((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 1)) << 8);
                  LODWORD(v989) = (_DWORD)v967 + 2;
                  i35 = -2007397661;
                }
                else
                {
                  if ( i35 == -673330124 )
                  {
                    v822 = *((unsigned __int8 *)&v1062[1] + (unsigned int)((_DWORD)v967 + 3)) << 24;
                    *((_DWORD *)&v1046 + (unsigned int)v966) = v822 & v973 | (v973 | (v965 << 16)) ^ v822;
                    v820 = (_DWORD)v966 + 1;
                    v819 = (_DWORD)v967 + 4;
                    goto LABEL_679;
                  }
                  LODWORD(v967) = v819;
                  LODWORD(v966) = v820;
                  i35 = -1614485789;
                  if ( v819 < 0x40 )
                    i35 = -942669483;
                }
              }
              if ( i35 != -2007397661 )
                break;
              v965 = *((_BYTE *)&v1062[1] + (unsigned int)v989);
            }
            v823 = v816 + __ROL4__((_DWORD)v1046 + (v818 & ~v816) + v815 + (v816 & v817) - 680876936, 7);
            v824 = v823 + __ROL4__(v818 + HIDWORD(v1046) + (v817 & ~v823) + (v816 & v823) - 389564586, 12);
            v984 = v818;
            v825 = v824 + __ROL4__(v1047 + v817 + (v816 & ~v824) + (v823 & v824) + 606105819, 17);
            v826 = v825 + __ROL4__(v816 + HIDWORD(v1047) + (v823 & ~v825) + (v824 & v825) - 1044525330, 22);
            v827 = v826 + __ROL4__((v825 & v826) + (v824 & ~v826) + v1048 + v823 - 176418897, 7);
            v828 = v827 + __ROL4__((v826 & v827) + (v825 & ~v827) + v1049 + v824 + 1200080426, 12);
            v829 = v828 + __ROL4__((v827 & v828) + (v826 & ~v828) + v1050 + v825 - 1473231341, 17);
            v830 = v829 + __ROL4__((v828 & v829) + (v827 & ~v829) + v1051 + v826 - 45705983, 22);
            v831 = v830 + __ROL4__((v829 & v830) + (v828 & ~v830) + v1052 + v827 + 1770035416, 7);
            v832 = v831 + __ROL4__((v830 & v831) + (v829 & ~v831) + v1053 + v828 - 1958414417, 12);
            v833 = v832 + __ROL4__((v831 & v832) + (v830 & ~v832) + v1054 + v829 - 42063, 17);
            v834 = v833 + __ROL4__((v832 & v833) + (v831 & ~v833) + v1055 + v830 - 1990404162, 22);
            v835 = v834 + __ROL4__((v833 & v834) + (v832 & ~v834) + v1056 + v831 + 1804603682, 7);
            v836 = v835 + __ROL4__((v833 & ~v835) + v1057 + v832 + (v834 & v835) - 40341101, 12);
            LODWORD(v1012) = v817;
            LODWORD(v1008) = v815;
            v837 = v836 + __ROL4__((~v836 & v834) + v1058 + v833 + (v835 & v836) - 1502002290, 17);
            v1007 = v816;
            v838 = v837 + __ROL4__((v836 & v837) + (~v837 & v835) + v1059 + v834 + 1236535329, 22);
            v839 = v838 + __ROL4__((v836 & v838) + HIDWORD(v1046) + v835 + (v837 & ~v836) - 165796510, 5);
            v840 = v839 + __ROL4__((v837 & v839) + (v838 & ~v837) + v1050 + v836 - 1069501632, 9);
            v841 = v840 + __ROL4__((v838 & v840) + (v839 & ~v838) + v1055 + v837 + 643717713, 14);
            v842 = v841 + __ROL4__((v839 & v841) + (v840 & ~v839) + (_DWORD)v1046 + v838 - 373897302, 20);
            v843 = v842 + __ROL4__((v840 & v842) + (v841 & ~v840) + v1049 + v839 - 701558691, 5);
            v844 = v843 + __ROL4__((v841 & v843) + (v842 & ~v841) + v1054 + v840 + 38016083, 9);
            v845 = v844 + __ROL4__((v842 & v844) + (v843 & ~v842) + v1059 + v841 - 660478335, 14);
            v846 = v845 + __ROL4__((v843 & v845) + (v844 & ~v843) + v1048 + v842 - 405537848, 20);
            v847 = v846 + __ROL4__((v844 & v846) + (v845 & ~v844) + v1053 + v843 + 568446438, 5);
            v848 = v847 + __ROL4__((v845 & v847) + (v846 & ~v845) + v1058 + v844 - 1019803690, 9);
            v849 = v848 + __ROL4__((v846 & v848) + (v847 & ~v846) + HIDWORD(v1047) + v845 - 187363961, 14);
            v850 = v849 + __ROL4__((v847 & v849) + (v848 & ~v847) + v1052 + v846 + 1163531501, 20);
            v851 = v850 + __ROL4__((v848 & v850) + (v849 & ~v848) + v1057 + v847 - 1444681467, 5);
            v852 = v851 + __ROL4__((v849 & v851) + (v850 & ~v849) + v1047 + v848 - 51403784, 9);
            v853 = v852 + __ROL4__((v850 & v852) + (v851 & ~v850) + v1051 + v849 + 1735328473, 14);
            v854 = v853 + __ROL4__((v851 & v853) + (v852 & ~v851) + v1056 + v850 - 1926607734, 20);
            v855 = v854 + __ROL4__((v852 ^ v853 ^ v854) + v1049 + v851 - 378558, 4);
            v856 = v855 + __ROL4__((v855 ^ v853 ^ v854) + v1052 + v852 - 2022574463, 11);
            v857 = v856 + __ROL4__((v854 ^ v855 ^ v856) + v1055 + v853 + 1839030562, 16);
            v858 = v857 + __ROL4__((v857 ^ v855 ^ v856) + v1058 + v854 - 35309556, 23);
            v859 = v858 + __ROL4__(HIDWORD(v1046) + v855 + (v856 ^ v857 ^ v858) - 1530992060, 4);
            v860 = v859 + __ROL4__(v1048 + v856 + (v859 ^ v857 ^ v858) + 1272893353, 11);
            v861 = v860 + __ROL4__((v858 ^ v859 ^ v860) + v1051 + v857 - 155497632, 16);
            v862 = v861 + __ROL4__((v861 ^ v859 ^ v860) + v1054 + v858 - 1094730640, 23);
            v863 = v862 + __ROL4__((v860 ^ v861 ^ v862) + v1057 + v859 + 681279174, 4);
            v864 = v863 + __ROL4__((v863 ^ v861 ^ v862) + (_DWORD)v1046 + v860 - 358537222, 11);
            v865 = v864 + __ROL4__((v864 ^ v862 ^ v863) + HIDWORD(v1047) + v861 - 722521979, 16);
            v866 = v865 + __ROL4__((v865 ^ v863 ^ v864) + v1050 + v862 + 76029189, 23);
            v867 = v866 + __ROL4__((v866 ^ v864 ^ v865) + v1053 + v863 - 640364487, 4);
            v868 = v867 + __ROL4__((v867 ^ v865 ^ v866) + v1056 + v864 - 421815835, 11);
            v869 = v868 + __ROL4__((v868 ^ v866 ^ v867) + v1059 + v865 + 530742520, 16);
            v870 = v869 + __ROL4__((v869 ^ v867 ^ v868) + v1047 + v866 - 995338651, 23);
            v871 = v870 + __ROL4__((v869 ^ (v870 | ~v868)) + (_DWORD)v1046 + v867 - 198630844, 6);
            v872 = v871 + __ROL4__((v870 ^ (v871 | ~v869)) + v1051 + v868 + 1126891415, 10);
            v873 = v872 + __ROL4__((v871 ^ (v872 | ~v870)) + v1058 + v869 - 1416354905, 15);
            v874 = v873 + __ROL4__((v872 ^ (v873 | ~v871)) + v1049 + v870 - 57434055, 21);
            v875 = v874 + __ROL4__((v873 ^ (v874 | ~v872)) + v1056 + v871 + 1700485571, 6);
            v876 = v875 + __ROL4__(HIDWORD(v1047) + v872 + (v874 ^ (v875 | ~v873)) - 1894986606, 10);
            v877 = v876 + __ROL4__((v875 ^ (~(v876 ^ v874) | v876 & ~v874)) + v1054 + v873 - 1051523, 15);
            v878 = v877 + __ROL4__((v876 ^ (v877 | ~v875)) + HIDWORD(v1046) + v874 - 2054922799, 21);
            v879 = v878 + __ROL4__((v877 ^ (v878 | ~v876)) + v1052 + v875 + 1873313359, 6);
            v880 = v879 + __ROL4__(v1059 + v876 + (v878 ^ (v879 | ~v877)) - 30611744, 10);
            v881 = v880 + __ROL4__((v879 ^ (~(v880 ^ v878) | v880 & ~v878)) + v1050 + v877 - 1560198380, 15);
            v882 = v881 + __ROL4__((v880 ^ (~(v879 ^ v881) | v881 & ~v879)) + v1057 + v878 + 1309151649, 21);
            v883 = v882 + __ROL4__(v1048 + v879 + (v881 ^ (v882 | ~v880)) - 145523070, 6);
            v884 = v883 + __ROL4__((v882 ^ (~(v883 ^ v881) | v883 & ~v881)) + v1055 + v880 - 1120210379, 10);
            v885 = v884 + __ROL4__(v1047 + v881 + (v883 ^ (v884 | ~v882)) + 718787259, 15);
            LODWORD(v1061[0]) = (_DWORD)v1008 + v883;
            HIDWORD(v1061[0]) = __ROL4__((v884 ^ (v885 | ~v883)) + v1053 + v882 - 343485551, 21) + v885 + v1007;
            LODWORD(v1061[1]) = v1012 + v885;
            HIDWORD(v1061[1]) = v984 + v884;
            v886 = 0;
LABEL_691:
            v887 = 976919488;
            while ( 1 )
            {
              while ( v887 <= -587301062 )
              {
                if ( v887 == -1016511951 )
                {
                  v886 = (unsigned int)v967;
                  goto LABEL_691;
                }
                *((_BYTE *)&v1046 + (int)v966) = 0;
                v887 = -455638576;
              }
              if ( v887 == -587301061 )
                break;
              if ( v887 == -455638576 )
              {
                LODWORD(v967) = (_DWORD)v966 + 1;
                v887 = -1016511951;
              }
              else
              {
                LODWORD(v966) = v886;
                v887 = -587301061;
                if ( v886 < 0x40 )
                  v887 = -588599311;
              }
            }
            i32 = 848251583;
            v802 = v977;
          }
          if ( i32 != 1916821574 )
            break;
          v804 = (char *)&v1061[-1] + v1033;
          v805 = *(_DWORD *)v975;
          v806 = *((_DWORD *)v975 + 1);
          v807 = *((_DWORD *)v975 + 2);
          LODWORD(v1012) = (_DWORD)v975;
          v808 = *((_DWORD *)v975 + 3);
          v809 = 0;
          v810 = 0;
LABEL_642:
          for ( i36 = 496118048; ; i36 = -673330124 )
          {
            while ( i36 > -942669484 )
            {
              if ( i36 == -942669483 )
              {
                v973 = (unsigned __int8)v804[(unsigned int)v967] | ((unsigned __int8)v804[(_DWORD)v967 + 1] << 8);
                LODWORD(v989) = (_DWORD)v967 + 2;
                i36 = -2007397661;
              }
              else
              {
                if ( i36 == -673330124 )
                {
                  v812 = (unsigned __int8)v804[(_DWORD)v967 + 3] << 24;
                  *((_DWORD *)&v1046 + (unsigned int)v966) = v812 & v973 | (v973 | (v965 << 16)) ^ v812;
                  v810 = (_DWORD)v966 + 1;
                  v809 = (_DWORD)v967 + 4;
                  goto LABEL_642;
                }
                LODWORD(v967) = v809;
                LODWORD(v966) = v810;
                i36 = -1614485789;
                if ( v809 < 0x40 )
                  i36 = -942669483;
              }
            }
            if ( i36 != -2007397661 )
              break;
            v965 = v804[(unsigned int)v989];
          }
          v888 = v806 + __ROL4__((_DWORD)v1046 + (v808 & ~v806) + v805 + (v806 & v807) - 680876936, 7);
          v889 = v888 + __ROL4__(HIDWORD(v1046) + v808 + (v807 & ~v888) + (v806 & v888) - 389564586, 12);
          LODWORD(v1008) = v806;
          v890 = v889 + __ROL4__(v807 + v1047 + (v806 & ~v889) + (v888 & v889) + 606105819, 17);
          v891 = v890 + __ROL4__((v889 & v890) + HIDWORD(v1047) + v806 + (v888 & ~v890) - 1044525330, 22);
          v892 = v891 + __ROL4__((v890 & v891) + (v889 & ~v891) + v1048 + v888 - 176418897, 7);
          LODWORD(v985) = v1049;
          v893 = v892 + __ROL4__((v891 & v892) + (v890 & ~v892) + v1049 + v889 + 1200080426, 12);
          v894 = v893 + __ROL4__((v892 & v893) + (v891 & ~v893) + v1050 + v890 - 1473231341, 17);
          v895 = v894 + __ROL4__((v893 & v894) + (v892 & ~v894) + v1051 + v891 - 45705983, 22);
          v896 = v895 + __ROL4__((v894 & v895) + (v893 & ~v895) + v1052 + v892 + 1770035416, 7);
          v897 = v896 + __ROL4__((v895 & v896) + (v894 & ~v896) + v1053 + v893 - 1958414417, 12);
          v898 = v897 + __ROL4__((v896 & v897) + (v895 & ~v897) + v1054 + v894 - 42063, 17);
          v899 = v898 + __ROL4__((v897 & v898) + (v896 & ~v898) + v1055 + v895 - 1990404162, 22);
          v900 = v899 + __ROL4__((v898 & v899) + (v897 & ~v899) + v1056 + v896 + 1804603682, 7);
          v901 = v900 + __ROL4__((v898 & ~v900) + v1057 + v897 + (v899 & v900) - 40341101, 12);
          v1007 = v808;
          v902 = v901 + __ROL4__((~v901 & v899) + v1058 + v898 + (v900 & v901) - 1502002290, 17);
          v994 = v805;
          v1002 = v807;
          v903 = v902 + __ROL4__((v901 & v902) + (~v902 & v900) + v1059 + v899 + 1236535329, 22);
          v904 = v903 + __ROL4__((v901 & v903) + HIDWORD(v1046) + v900 + (v902 & ~v901) - 165796510, 5);
          v905 = v904 + __ROL4__((v902 & v904) + (v903 & ~v902) + v1050 + v901 - 1069501632, 9);
          v906 = v905 + __ROL4__((v903 & v905) + (v904 & ~v903) + v1055 + v902 + 643717713, 14);
          v907 = v906 + __ROL4__((v904 & v906) + (v905 & ~v904) + (_DWORD)v1046 + v903 - 373897302, 20);
          v908 = v907 + __ROL4__((v905 & v907) + (v906 & ~v905) + v1049 + v904 - 701558691, 5);
          v909 = v908 + __ROL4__((v906 & v908) + (v907 & ~v906) + v1054 + v905 + 38016083, 9);
          v910 = v909 + __ROL4__((v907 & v909) + (v908 & ~v907) + v1059 + v906 - 660478335, 14);
          v911 = v910 + __ROL4__((v908 & v910) + (v909 & ~v908) + v1048 + v907 - 405537848, 20);
          v912 = v911 + __ROL4__((v909 & v911) + (v910 & ~v909) + v1053 + v908 + 568446438, 5);
          v913 = v912 + __ROL4__((v910 & v912) + (v911 & ~v910) + v1058 + v909 - 1019803690, 9);
          v914 = v913 + __ROL4__((v911 & v913) + (v912 & ~v911) + HIDWORD(v1047) + v910 - 187363961, 14);
          v915 = v914 + __ROL4__((v912 & v914) + (v913 & ~v912) + v1052 + v911 + 1163531501, 20);
          v916 = v915 + __ROL4__((v913 & v915) + (v914 & ~v913) + v1057 + v912 - 1444681467, 5);
          v917 = v916 + __ROL4__((v914 & v916) + (v915 & ~v914) + v1047 + v913 - 51403784, 9);
          v918 = v917 + __ROL4__((v915 & v917) + (v916 & ~v915) + v1051 + v914 + 1735328473, 14);
          v919 = v918 + __ROL4__((v916 & v918) + (v917 & ~v916) + v1056 + v915 - 1926607734, 20);
          v920 = v919 + __ROL4__((v917 ^ v918 ^ v919) + v1049 + v916 - 378558, 4);
          v921 = v920 + __ROL4__((v920 ^ v918 ^ v919) + v1052 + v917 - 2022574463, 11);
          v922 = v921 + __ROL4__(v1055 + v918 + (v919 ^ v920 ^ v921) + 1839030562, 16);
          v923 = v922 + __ROL4__((v922 ^ v920 ^ v921) + v1058 + v919 - 35309556, 23);
          v924 = v923 + __ROL4__((v921 ^ v922 ^ v923) + HIDWORD(v1046) + v920 - 1530992060, 4);
          v925 = v924 + __ROL4__((v924 ^ v922 ^ v923) + v1048 + v921 + 1272893353, 11);
          v926 = v925 + __ROL4__(v1051 + v922 + (v923 ^ v924 ^ v925) - 155497632, 16);
          v927 = v926 + __ROL4__((v926 ^ v924 ^ v925) + v1054 + v923 - 1094730640, 23);
          v928 = v927 + __ROL4__(v1057 + v924 + (v925 ^ v926 ^ v927) + 681279174, 4);
          v929 = v928 + __ROL4__((v928 ^ v926 ^ v927) + (_DWORD)v1046 + v925 - 358537222, 11);
          v930 = v929 + __ROL4__((v929 ^ v927 ^ v928) + HIDWORD(v1047) + v926 - 722521979, 16);
          v931 = v930 + __ROL4__(v1050 + v927 + (v930 ^ v928 ^ v929) + 76029189, 23);
          v932 = v931 + __ROL4__((v931 ^ v929 ^ v930) + v1053 + v928 - 640364487, 4);
          v933 = v932 + __ROL4__((v932 ^ v930 ^ v931) + v1056 + v929 - 421815835, 11);
          v934 = v933 + __ROL4__(v1059 + v930 + (v933 ^ v931 ^ v932) + 530742520, 16);
          v935 = v934 + __ROL4__((v934 ^ v932 ^ v933) + v1047 + v931 - 995338651, 23);
          v936 = v935 + __ROL4__((v934 ^ (v935 | ~v933)) + (_DWORD)v1046 + v932 - 198630844, 6);
          v937 = v936 + __ROL4__((v935 ^ (v936 | ~v934)) + v1051 + v933 + 1126891415, 10);
          v938 = v937 + __ROL4__((v936 ^ (v937 | ~v935)) + v1058 + v934 - 1416354905, 15);
          v939 = v938 + __ROL4__((v937 ^ (v938 | ~v936)) + v1049 + v935 - 57434055, 21);
          v940 = v939 + __ROL4__((v938 ^ (v939 | ~v937)) + v1056 + v936 + 1700485571, 6);
          v941 = v940 + __ROL4__((v939 ^ (v940 | ~v938)) + HIDWORD(v1047) + v937 - 1894986606, 10);
          v942 = v941 + __ROL4__(v1054 + v938 + (v940 ^ (~(v941 ^ v939) | v941 & ~v939)) - 1051523, 15);
          v943 = v942 + __ROL4__((v941 ^ (v942 | ~v940)) + HIDWORD(v1046) + v939 - 2054922799, 21);
          v944 = v943 + __ROL4__(v1052 + v940 + (v942 ^ (v943 | ~v941)) + 1873313359, 6);
          v945 = v944 + __ROL4__((v943 ^ (v944 | ~v942)) + v1059 + v941 - 30611744, 10);
          v946 = v945 + __ROL4__((v944 ^ (~(v945 ^ v943) | v945 & ~v943)) + v1050 + v942 - 1560198380, 15);
          v947 = v946 + __ROL4__(v1057 + v943 + (v945 ^ (~(v944 ^ v946) | v946 & ~v944)) + 1309151649, 21);
          v948 = v947 + __ROL4__((v946 ^ (v947 | ~v945)) + v1048 + v944 - 145523070, 6);
          v949 = v948 + __ROL4__((v947 ^ (~(v948 ^ v946) | v948 & ~v946)) + v1055 + v945 - 1120210379, 10);
          v950 = v949 + __ROL4__((v948 ^ (v949 | ~v947)) + v1047 + v946 + 718787259, 15);
          v951 = (v949 ^ (v950 | ~v948)) + v1053 + v947 - 343485551;
          *(_DWORD *)v975 = v994 + v948;
          *((_DWORD *)v975 + 1) = __ROL4__(v951, 21) + v950 + (_DWORD)v1008;
          *((_DWORD *)v975 + 2) = v1002 + v950;
          *((_DWORD *)v975 + 3) = v1007 + v949;
          v952 = 0;
LABEL_703:
          v953 = 976919488;
          while ( 1 )
          {
            while ( v953 <= -587301062 )
            {
              if ( v953 == -1016511951 )
              {
                v952 = (unsigned int)v967;
                goto LABEL_703;
              }
              *((_BYTE *)&v1046 + (int)v966) = 0;
              v953 = -455638576;
            }
            if ( v953 == -587301061 )
              break;
            if ( v953 == -455638576 )
            {
              LODWORD(v967) = (_DWORD)v966 + 1;
              v953 = -1016511951;
            }
            else
            {
              LODWORD(v966) = v952;
              v953 = -587301061;
              if ( v952 < 0x40 )
                v953 = -588599311;
            }
          }
          v802 = v1033 + 64;
        }
        for ( i37 = 0; ; i37 = (_DWORD)v966 + 1 )
        {
          for ( i38 = -1785266232; ; i38 = -1827872406 )
          {
            while ( i38 <= -1207850492 )
            {
              if ( i38 == -1827872406 )
              {
                *((_BYTE *)v1046 + (_QWORD)&v1062[1] + (unsigned int)v1013) = *((_BYTE *)&v1061[-1]
                                                                              + (_QWORD)v1046
                                                                              + (unsigned int)v1011);
                i38 = 976403079;
              }
              else
              {
                LODWORD(v966) = i37;
                i38 = -554264179;
                if ( i37 < 8 - (int)v1011 )
                  i38 = -1207850491;
              }
            }
            if ( i38 != -1207850491 )
              break;
            v1046 = (void *)(int)v966;
          }
          if ( i38 == -554264179 )
            break;
        }
        v956 = 0;
        v957 = 0;
LABEL_728:
        for ( i39 = -1717192363; ; i39 = -2031488434 )
        {
          while ( 1 )
          {
            while ( i39 <= -736119120 )
            {
              if ( i39 == -2031488434 )
              {
                *((_BYTE *)ptr + (unsigned int)v978) = (_BYTE)v966;
                v957 = (_DWORD)v975 + 1;
                v956 = (_DWORD)v972 + 4;
                goto LABEL_728;
              }
              LODWORD(v972) = v956;
              LODWORD(v975) = v957;
              i39 = 494299060;
              if ( v956 < 0x10 )
                i39 = -736119119;
            }
            if ( i39 != -736119119 )
              break;
            v1046 = (char *)v1061 + 4 * (unsigned int)v975;
            *((_BYTE *)ptr + (unsigned int)v972) = *(_BYTE *)v1046;
            *((_BYTE *)ptr + (unsigned int)((_DWORD)v972 + 1)) = *((_BYTE *)v1046 + 1);
            *((_BYTE *)ptr + (unsigned int)((_DWORD)v972 + 2)) = *((_BYTE *)v1046 + 2);
            i39 = 1223234202;
          }
          if ( i39 == 494299060 )
            break;
          LOBYTE(v966) = *((_BYTE *)v1046 + 3);
          LODWORD(v978) = (_DWORD)v972 + 3;
        }
        v959 = 0;
LABEL_740:
        v960 = 976919488;
        while ( 1 )
        {
          while ( v960 <= -587301062 )
          {
            if ( v960 == -1016511951 )
            {
              v959 = (unsigned int)v975;
              goto LABEL_740;
            }
            *((_BYTE *)v1061 + (int)v1046) = 0;
            v960 = -455638576;
          }
          if ( v960 == -587301061 )
            break;
          if ( v960 == -455638576 )
          {
            LODWORD(v975) = (_DWORD)v1046 + 1;
            v960 = -1016511951;
          }
          else
          {
            LODWORD(v1046) = v959;
            v960 = -587301061;
            if ( v959 < 0x58 )
              v960 = -588599311;
          }
        }
        LOBYTE(v978) = 0;
        for ( i40 = 486138542; i40 != 55239270; i40 = 55239270 )
          ;
        for ( i41 = 0; ; i41 = (_DWORD)v975 + 1 )
        {
          for ( i42 = -1785266232; ; i42 = -1827872406 )
          {
            while ( i42 <= -1207850492 )
            {
              if ( i42 == -1827872406 )
              {
                *((_BYTE *)&v1036 + (_QWORD)v1046) = *((_BYTE *)ptr + (_QWORD)v1046);
                i42 = 976403079;
              }
              else
              {
                LODWORD(v975) = i41;
                i42 = -554264179;
                if ( i41 < 0x10 )
                  i42 = -1207850491;
              }
            }
            if ( i42 != -1207850491 )
              break;
            v1046 = (void *)(int)v975;
          }
          if ( i42 == -554264179 )
            break;
        }
        LODWORD(v4) = 1940450848;
      }
    }
    if ( (_DWORD)v4 == 1686634351 )
    {
      sub_56B4244(v1042);
      LODWORD(v4) = 451461577;
      goto LABEL_2;
    }
    if ( (_DWORD)v4 != 1940450848 )
      break;
    v7 = strlen(a2);
    v1034[0] = v1035;
    std::string::_M_construct<char const*>(v1034, a2, &a2[v7]);
    v1061[0] = v1062;
    std::string::_M_construct<char const*>(v1061, v1030, v1030 + 1);
    v1046 = &v1048;
    v8 = sub_56F9F18(&buf);
    std::string::_M_construct<char const*>(&v1046, &buf, &buf + v8);
    v989 = v1061[0];
    v967 = v1061[1];
    v966 = v1046;
    LODWORD(v9) = -1345118485;
    do
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( (int)v9 <= -486284406 )
            {
              if ( (int)v9 <= -1472114617 )
              {
                switch ( (_DWORD)v9 )
                {
                  case 0x8FEF0CDA:
                    goto LABEL_59;
                  case 0xA5062647:
                    *a1 = v1026;
                    v10 = sub_56F9F18(&buf);
                    std::string::_M_construct<char const*>(a1, &buf, &buf + v10);
LABEL_59:
                    LODWORD(v9) = 1895476407;
                    break;
                  case 0xA60356D8:
                    *a1 = v1026;
                    std::string::_M_construct<char const*>(a1, v1024, (char *)v978 + (_QWORD)v1024);
                    LODWORD(v9) = 1017348971;
                    break;
                }
              }
              else if ( (int)v9 > -1121779496 )
              {
                if ( (_DWORD)v9 == -1121779495 )
                {
                  free(v1060);
                  LODWORD(v9) = -1880159014;
                }
                else if ( (_DWORD)v9 == -715389597 )
                {
                  LODWORD(v9) = -1509730600;
                }
              }
              else if ( (_DWORD)v9 == -1472114616 )
              {
                LODWORD(v9) = -1526323641;
                if ( (_BYTE)v973 )
                  LODWORD(v9) = 1500195160;
              }
              else if ( (_DWORD)v9 == -1345118485 )
              {
                v1060 = (void *)sub_5CCC307(v1034, v989, v967, v966, v1047);
                LOBYTE(v973) = v1060 != 0;
                LODWORD(v9) = -1472114616;
              }
            }
            if ( (int)v9 > 1236086356 )
              break;
            if ( (int)v9 > 196235302 )
            {
              if ( (_DWORD)v9 == 196235303 )
              {
                LODWORD(v9) = -1121779495;
              }
              else if ( (_DWORD)v9 == 1017348971 )
              {
                v975 = (void **)*v1021;
                LODWORD(v9) = -486284405;
                if ( !*v1021 )
                  LODWORD(v9) = -1121779495;
              }
            }
            else if ( (_DWORD)v9 == -486284405 )
            {
              memset(v975, 0, *v968);
              ptr[0] = *v1021;
              v9 = &loc_3638F56;
            }
            else if ( (_DWORD)v9 == (_DWORD)&loc_3638F56 )
            {
              free(ptr[0]);
              *v1021 = 0;
              LODWORD(v9) = 196235303;
            }
          }
          if ( (int)v9 > 1500195159 )
            break;
          if ( (_DWORD)v9 == 1236086357 )
          {
            LODWORD(v9) = 1895476407;
            if ( *a1 != v1026 )
              operator delete(*a1);
          }
          else if ( (_DWORD)v9 == 1474665819 )
          {
            v968 = (unsigned int *)v1060;
            v978 = (_QWORD *)*(unsigned int *)v1060;
            LODWORD(v9) = -715389597;
          }
        }
        if ( (_DWORD)v9 != 1500195160 )
          break;
        v1021 = (void **)((char *)v1060 + 8);
        v1024 = (void **)*((_QWORD *)v1060 + 1);
        LODWORD(v9) = 1474665819;
        if ( !v1024 )
          LODWORD(v9) = -1526323641;
      }
    }
    while ( (_DWORD)v9 != 1895476407 );
    if ( v1046 != &v1048 )
      operator delete(v1046);
    if ( v1061[0] != v1062 )
      operator delete(v1061[0]);
    if ( v1034[0] != v1035 )
      operator delete(v1034[0]);
    if ( v1037 != &v1039 )
      operator delete(v1037);
    if ( v1040[0] != &v1041 )
      operator delete(v1040[0]);
    if ( v1042[0] != &v1043 )
      operator delete(v1042[0]);
  }
  if ( (_DWORD)v4 != 2111984431 )
    goto LABEL_2;
  return a1;
}


// ===== sub_56C3008 @ 0x56c3008 (size 0x16b8) =====
_QWORD *__fastcall sub_56C3008(_QWORD *a1, char *a2, size_t a3)
{
  __int64 v3; // r15
  size_t v4; // rbx
  unsigned __int64 v5; // r14
  _QWORD *v6; // rcx
  int v7; // eax
  int j; // eax
  size_t v9; // r12
  int k; // eax
  int v11; // ecx
  size_t *v12; // rax
  size_t v13; // rcx
  __int64 v14; // rax
  int v15; // ecx
  _BYTE *v16; // rax
  int v17; // eax
  int m; // eax
  size_t v19; // r12
  int v20; // r14d
  int ii; // eax
  int v22; // ecx
  int v23; // eax
  int jj; // eax
  size_t v25; // r12
  int v26; // r14d
  int kk; // eax
  int v28; // ecx
  int mm; // eax
  int v30; // ecx
  _BYTE *v31; // rax
  int i; // eax
  int v33; // eax
  int v34; // eax
  __int64 v36; // [rsp+0h] [rbp-210h] BYREF
  _QWORD *v37; // [rsp+8h] [rbp-208h]
  __int64 *v38; // [rsp+10h] [rbp-200h]
  void **v39; // [rsp+18h] [rbp-1F8h]
  __int64 (__fastcall ***v40)(); // [rsp+20h] [rbp-1F0h]
  void **v41; // [rsp+28h] [rbp-1E8h]
  _QWORD *v42; // [rsp+30h] [rbp-1E0h]
  char *v43; // [rsp+38h] [rbp-1D8h]
  char *v44; // [rsp+40h] [rbp-1D0h]
  void **v45; // [rsp+48h] [rbp-1C8h]
  char *s1; // [rsp+50h] [rbp-1C0h]
  _QWORD *v47; // [rsp+58h] [rbp-1B8h]
  __int64 *v48; // [rsp+60h] [rbp-1B0h]
  _QWORD *v49; // [rsp+68h] [rbp-1A8h]
  unsigned __int64 v50; // [rsp+70h] [rbp-1A0h]
  unsigned __int64 *v51; // [rsp+78h] [rbp-198h]
  char *v52; // [rsp+80h] [rbp-190h]
  char v53; // [rsp+8Fh] [rbp-181h]
  _QWORD *v54; // [rsp+90h] [rbp-180h] BYREF
  unsigned __int64 v55; // [rsp+98h] [rbp-178h] BYREF
  unsigned __int64 v56; // [rsp+A0h] [rbp-170h] BYREF
  void *v57[2]; // [rsp+A8h] [rbp-168h] BYREF
  _BYTE v58[16]; // [rsp+B8h] [rbp-158h] BYREF
  void *v59; // [rsp+C8h] [rbp-148h] BYREF
  size_t n[3]; // [rsp+D0h] [rbp-140h] BYREF
  char v61; // [rsp+E8h] [rbp-128h] BYREF
  _BYTE v62[47]; // [rsp+E9h] [rbp-127h] BYREF
  _BYTE v63[2]; // [rsp+118h] [rbp-F8h] BYREF
  char v64; // [rsp+11Ah] [rbp-F6h] BYREF
  char v65; // [rsp+120h] [rbp-F0h] BYREF
  _BYTE v66[52]; // [rsp+121h] [rbp-EFh] BYREF
  _BYTE v67[2]; // [rsp+155h] [rbp-BBh] BYREF
  char v68; // [rsp+157h] [rbp-B9h] BYREF
  __int64 (__fastcall **v69)(); // [rsp+158h] [rbp-B8h] BYREF
  void *dest; // [rsp+160h] [rbp-B0h]
  __int128 v71; // [rsp+168h] [rbp-A8h] BYREF
  void *v72; // [rsp+180h] [rbp-90h] BYREF
  unsigned __int64 v73; // [rsp+188h] [rbp-88h]
  _BYTE v74[16]; // [rsp+190h] [rbp-80h] BYREF
  void *v75; // [rsp+1A0h] [rbp-70h]
  unsigned __int64 v76; // [rsp+1A8h] [rbp-68h]
  _BYTE v77[16]; // [rsp+1B0h] [rbp-60h] BYREF
  void *v78[2]; // [rsp+1C0h] [rbp-50h] BYREF
  char v79; // [rsp+1D0h] [rbp-40h] BYREF
  unsigned __int64 v80; // [rsp+1E0h] [rbp-30h]

  v37 = (_QWORD *)a3;
  s1 = a2;
  v80 = __readfsqword(0x28u);
  v47 = a1;
  v42 = a1 + 2;
  LODWORD(v4) = -1462857936;
  v5 = 1841140526;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( (int)v4 > -994720243 )
        {
          if ( (int)v4 <= -524878486 )
          {
            v39 = &v59;
            LODWORD(v4) = 727991294;
          }
          else if ( (_DWORD)v4 == -524878485 )
          {
            v61 = 1;
            qmemcpy(v62, "/tqrf*h5'mhneSnmru`a;QtrqYxyxol0rSLq@GRTLiHIH_\\", sizeof(v62));
            v56 = (unsigned __int64)&v64;
            v30 = 709999357;
            v31 = v63;
            while ( v30 != -1768845522 )
            {
              *v31++ = 0;
              v30 = 709999357;
              if ( v31 == (_BYTE *)v56 )
                v30 = -1768845522;
            }
            v52 = &v61;
            LOBYTE(v54) = v61;
            for ( i = -1750127840; ; i = 219469916 )
            {
              while ( 1 )
              {
                while ( i <= 886749394 )
                {
                  if ( i > -1130052023 )
                  {
                    if ( i == -1130052022 )
                    {
                      *(_BYTE *)(v50 + v55++) = ((-2 - (_BYTE)v49) & 0xF6 | ((_BYTE)v49 + 1) & 9)
                                              ^ v62[0]
                                              ^ *(_BYTE *)(v50 + v56)
                                              ^ 0xD8;
                      i = 916962057;
                    }
                    else
                    {
                      v50 = (unsigned __int64)&v62[1];
                      v56 = v55;
                      i = -1130052022;
                    }
                  }
                  else if ( i == -1750127840 )
                  {
                    i = -1324268074;
                    if ( ((unsigned __int8)v54 & 1) == 0 )
                      i = 983019210;
                  }
                  else
                  {
                    v51 = &v55;
                    v55 = 0;
                    i = 916962057;
                  }
                }
                if ( i > 983019209 )
                  break;
                if ( i == 886749395 )
                {
                  v63[0] = 0;
                  v63[1] = 0;
                  *v52 = 0;
                  i = 983019210;
                }
                else
                {
                  i = 886749395;
                  if ( v55 < 0x2E )
                    i = 1841140526;
                }
              }
              if ( i != 1841140526 )
                break;
              LODWORD(v49) = v55;
            }
            LODWORD(v4) = -1210111580;
            if ( !strcmp(s1, &v62[1]) )
              LODWORD(v4) = -994720242;
          }
          else if ( (_DWORD)v4 == 727991294 )
          {
            v3 = sub_56956B8();
            v57[0] = v58;
            std::string::_M_construct<char *>(v57, *v37, *v37 + v37[1]);
            v38 = v48;
            sub_56957EC(v45, s1, v48);
            sub_5A593EA(&v59, v3, v57, v45);
            if ( v59 == &n[1] )
            {
              a3 = n[0];
              if ( n[0] )
              {
                if ( n[0] == 1 )
                  *(_BYTE *)dest = n[1];
                else
                  memcpy(dest, &n[1], n[0]);
              }
              *(_QWORD *)&v71 = n[0];
              *((_BYTE *)dest + n[0]) = 0;
              v12 = (size_t *)v59;
            }
            else
            {
              v12 = (size_t *)dest;
              v13 = *((_QWORD *)&v71 + 1);
              dest = v59;
              v71 = *(_OWORD *)n;
              a3 = (size_t)&v71 + 8;
              if ( v12 == (size_t *)((char *)&v71 + 8) || !v12 )
              {
                v59 = &n[1];
                v12 = &n[1];
              }
              else
              {
                v59 = v12;
                n[1] = v13;
              }
            }
            n[0] = 0;
            *(_BYTE *)v12 = 0;
            if ( v59 != &n[1] )
              operator delete(v59);
            if ( *v45 != v45 + 2 )
              operator delete(*v45);
            LODWORD(v4) = 1187090530;
          }
          else
          {
            if ( v57[0] != v58 )
              operator delete(v57[0]);
            LODWORD(v4) = -1210111580;
          }
        }
        if ( (int)v4 <= -1462857937 )
          break;
        if ( (_DWORD)v4 == -1462857936 )
        {
          v45 = (void **)(&v36 - 4);
          v48 = &v36 - 2;
          v41 = v78;
          v14 = sub_56C2E3E();
          sub_56957EC(v78, *(_QWORD *)(v14 + 64), &v56);
          v40 = &v69;
          v69 = &off_7CA2830;
          dest = (char *)&v71 + 8;
          *(_QWORD *)&v71 = 0;
          BYTE8(v71) = 0;
          v72 = v74;
          v73 = 0;
          v74[0] = 0;
          v75 = v77;
          v76 = 0;
          v77[0] = 0;
          std::string::_M_assign(&v72, v78);
          v44 = &v65;
          v65 = 1;
          qmemcpy(v66, "/ilo{7u(:pusxNspoh}|&LiolDederq-oNQzKM[YX\\E_cYSAIfKV", sizeof(v66));
          LOBYTE(a3) = 111;
          v56 = (unsigned __int64)&v68;
          v15 = 1684683030;
          v16 = v67;
          while ( v15 != -815025497 )
          {
            *v16++ = 0;
            v15 = 1684683030;
            a3 = 3479941799LL;
            if ( v16 == (_BYTE *)v56 )
              v15 = -815025497;
          }
          LODWORD(v4) = -2044314777;
        }
        else
        {
          v6 = v47;
          *v47 = v42;
          v6[1] = 0;
          *((_BYTE *)v6 + 16) = 0;
          v49 = &v54;
          v54 = v6;
          v55 = v71;
          v7 = 15683199;
          while ( v7 != -1747789055 )
          {
            if ( v7 == -905888113 )
            {
              for ( j = 693113538; ; j = -170651053 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( j > 693113537 )
                    {
                      if ( j > 1563511586 )
                      {
                        if ( j == 1563511587 )
                        {
                          LOBYTE(v4) = v53 | 0x80;
                          j = -475423977;
                        }
                        else
                        {
                          j = 1072704708;
                          if ( !v52 )
                            j = -1340685559;
                        }
                      }
                      else if ( j == 693113538 )
                      {
                        j = -1752948638;
                        v5 = 10;
                      }
                      else
                      {
                        v50 = *v51;
                        j = -1331101447;
                      }
                    }
                    if ( j <= -475423978 )
                      break;
                    if ( j == -475423977 )
                    {
                      v52 = (char *)(v56 >> 7);
                      v51 = (unsigned __int64 *)&v54;
                      sub_56E41BA(v54, (unsigned int)(char)v4);
                      j = 1696537547;
                      if ( (unsigned __int64)v52 > 0x7F )
                        j = -1752948638;
                      v5 = (unsigned __int64)v52;
                    }
                    else
                    {
                      j = -1340685559;
                    }
                  }
                  if ( j != -1752948638 )
                    break;
                  v56 = v5;
                  v53 = v5;
                  j = -475423977;
                  if ( v5 >= 0x81 )
                    j = 1563511587;
                  LOBYTE(v4) = v53;
                }
                if ( j != -1331101447 )
                  break;
                sub_56E41BA(v50, (unsigned int)(char)v52);
              }
              v9 = v71;
              LODWORD(v4) = -1752948638;
              if ( !(_QWORD)v71 )
                LODWORD(v4) = -1340685559;
              for ( k = 693113538; ; k = -170651053 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      v11 = k;
                      v3 = a3;
                      if ( k <= 693113537 )
                        break;
                      if ( k > 1563511586 )
                      {
                        if ( k == 1563511587 )
                        {
                          LOBYTE(v5) = v53 | 0x80;
                          k = -475423977;
                        }
                        else
                        {
                          k = 1072704708;
                          if ( !v52 )
                            k = -1340685559;
                        }
                      }
                      else
                      {
                        a3 = v9;
                        k = v4;
                        if ( v11 != 693113538 )
                        {
                          a3 = v3;
                          k = v11;
                          if ( v11 == 1072704708 )
                          {
                            v50 = *v51;
                            k = -1331101447;
                            a3 = v3;
                          }
                        }
                      }
                    }
                    if ( k <= -475423978 )
                      break;
                    if ( k == -475423977 )
                    {
                      v52 = (char *)(v56 >> 7);
                      v51 = (unsigned __int64 *)&v54;
                      sub_56E41BA(v54, (unsigned int)(char)v5);
                      k = 1696537547;
                      if ( (unsigned __int64)v52 > 0x7F )
                        k = -1752948638;
                      a3 = (size_t)v52;
                    }
                    else
                    {
                      k = -1340685559;
                    }
                  }
                  if ( k != -1752948638 )
                    break;
                  v56 = a3;
                  v53 = a3;
                  k = -475423977;
                  if ( a3 >= 0x81 )
                    k = 1563511587;
                  LOBYTE(v5) = v53;
                }
                if ( k != -1331101447 )
                  break;
                sub_56E41BA(v50, (unsigned int)(char)v52);
                a3 = v3;
              }
              std::string::_M_append(v54, dest, v71);
              v7 = -1747789055;
              v5 = 1841140526;
            }
            else
            {
              v7 = -905888113;
              if ( !v55 )
                v7 = -1747789055;
            }
          }
          v55 = v73;
          v17 = 15683199;
          while ( v17 != -1747789055 )
          {
            if ( v17 == -905888113 )
            {
              for ( m = 693113538; ; m = -170651053 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( m > 693113537 )
                    {
                      if ( m > 1563511586 )
                      {
                        if ( m == 1563511587 )
                        {
                          LOBYTE(v4) = v53 | 0x80;
                          m = -475423977;
                        }
                        else
                        {
                          m = 1072704708;
                          if ( !v52 )
                            m = -1340685559;
                        }
                      }
                      else if ( m == 693113538 )
                      {
                        m = -1752948638;
                        v5 = 18;
                      }
                      else
                      {
                        v50 = *v51;
                        m = -1331101447;
                      }
                    }
                    if ( m <= -475423978 )
                      break;
                    if ( m == -475423977 )
                    {
                      v52 = (char *)(v56 >> 7);
                      v51 = (unsigned __int64 *)&v54;
                      sub_56E41BA(v54, (unsigned int)(char)v4);
                      m = 1696537547;
                      if ( (unsigned __int64)v52 > 0x7F )
                        m = -1752948638;
                      v5 = (unsigned __int64)v52;
                    }
                    else
                    {
                      m = -1340685559;
                    }
                  }
                  if ( m != -1752948638 )
                    break;
                  v56 = v5;
                  v53 = v5;
                  m = -475423977;
                  if ( v5 >= 0x81 )
                    m = 1563511587;
                  LOBYTE(v4) = v53;
                }
                if ( m != -1331101447 )
                  break;
                sub_56E41BA(v50, (unsigned int)(char)v52);
              }
              v19 = v73;
              v20 = -1752948638;
              if ( !v73 )
                v20 = -1340685559;
              for ( ii = 693113538; ; ii = -170651053 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      v22 = ii;
                      v4 = a3;
                      if ( ii <= 693113537 )
                        break;
                      if ( ii > 1563511586 )
                      {
                        if ( ii == 1563511587 )
                        {
                          LOBYTE(v3) = v53 | 0x80;
                          ii = -475423977;
                        }
                        else
                        {
                          ii = 1072704708;
                          if ( !v52 )
                            ii = -1340685559;
                        }
                      }
                      else
                      {
                        a3 = v19;
                        ii = v20;
                        if ( v22 != 693113538 )
                        {
                          a3 = v4;
                          ii = v22;
                          if ( v22 == 1072704708 )
                          {
                            v50 = *v51;
                            ii = -1331101447;
                            a3 = v4;
                          }
                        }
                      }
                    }
                    if ( ii <= -475423978 )
                      break;
                    if ( ii == -475423977 )
                    {
                      v52 = (char *)(v56 >> 7);
                      v51 = (unsigned __int64 *)&v54;
                      sub_56E41BA(v54, (unsigned int)(char)v3);
                      ii = 1696537547;
                      if ( (unsigned __int64)v52 > 0x7F )
                        ii = -1752948638;
                      a3 = (size_t)v52;
                    }
                    else
                    {
                      ii = -1340685559;
                    }
                  }
                  if ( ii != -1752948638 )
                    break;
                  v56 = a3;
                  v53 = a3;
                  ii = -475423977;
                  if ( a3 >= 0x81 )
                    ii = 1563511587;
                  LOBYTE(v3) = v53;
                }
                if ( ii != -1331101447 )
                  break;
                sub_56E41BA(v50, (unsigned int)(char)v52);
                a3 = v4;
              }
              std::string::_M_append(v54, v72, v73);
              v17 = -1747789055;
              v5 = 1841140526;
            }
            else
            {
              v17 = -905888113;
              if ( !v55 )
                v17 = -1747789055;
            }
          }
          v55 = v76;
          v23 = 15683199;
          while ( v23 != -1747789055 )
          {
            if ( v23 == -905888113 )
            {
              for ( jj = 693113538; ; jj = -170651053 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( jj > 693113537 )
                    {
                      if ( jj > 1563511586 )
                      {
                        if ( jj == 1563511587 )
                        {
                          LOBYTE(v4) = v53 | 0x80;
                          jj = -475423977;
                        }
                        else
                        {
                          jj = 1072704708;
                          if ( !v52 )
                            jj = -1340685559;
                        }
                      }
                      else if ( jj == 693113538 )
                      {
                        jj = -1752948638;
                        v5 = 26;
                      }
                      else
                      {
                        v50 = *v51;
                        jj = -1331101447;
                      }
                    }
                    if ( jj <= -475423978 )
                      break;
                    if ( jj == -475423977 )
                    {
                      v52 = (char *)(v56 >> 7);
                      v51 = (unsigned __int64 *)&v54;
                      sub_56E41BA(v54, (unsigned int)(char)v4);
                      jj = 1696537547;
                      if ( (unsigned __int64)v52 > 0x7F )
                        jj = -1752948638;
                      v5 = (unsigned __int64)v52;
                    }
                    else
                    {
                      jj = -1340685559;
                    }
                  }
                  if ( jj != -1752948638 )
                    break;
                  v56 = v5;
                  v53 = v5;
                  jj = -475423977;
                  if ( v5 >= 0x81 )
                    jj = 1563511587;
                  LOBYTE(v4) = v53;
                }
                if ( jj != -1331101447 )
                  break;
                sub_56E41BA(v50, (unsigned int)(char)v52);
              }
              v25 = v76;
              v26 = -1752948638;
              if ( !v76 )
                v26 = -1340685559;
              for ( kk = 693113538; ; kk = -170651053 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      v28 = kk;
                      v4 = a3;
                      if ( kk <= 693113537 )
                        break;
                      if ( kk > 1563511586 )
                      {
                        if ( kk == 1563511587 )
                        {
                          LOBYTE(v3) = v53 | 0x80;
                          kk = -475423977;
                        }
                        else
                        {
                          kk = 1072704708;
                          if ( !v52 )
                            kk = -1340685559;
                        }
                      }
                      else
                      {
                        a3 = v25;
                        kk = v26;
                        if ( v28 != 693113538 )
                        {
                          a3 = v4;
                          kk = v28;
                          if ( v28 == 1072704708 )
                          {
                            v50 = *v51;
                            kk = -1331101447;
                            a3 = v4;
                          }
                        }
                      }
                    }
                    if ( kk <= -475423978 )
                      break;
                    if ( kk == -475423977 )
                    {
                      v52 = (char *)(v56 >> 7);
                      v51 = (unsigned __int64 *)&v54;
                      sub_56E41BA(v54, (unsigned int)(char)v3);
                      kk = 1696537547;
                      if ( (unsigned __int64)v52 > 0x7F )
                        kk = -1752948638;
                      a3 = (size_t)v52;
                    }
                    else
                    {
                      kk = -1340685559;
                    }
                  }
                  if ( kk != -1752948638 )
                    break;
                  v56 = a3;
                  v53 = a3;
                  kk = -475423977;
                  if ( a3 >= 0x81 )
                    kk = 1563511587;
                  LOBYTE(v3) = v53;
                }
                if ( kk != -1331101447 )
                  break;
                sub_56E41BA(v50, (unsigned int)(char)v52);
                a3 = v4;
              }
              std::string::_M_append(v54, v75, v76);
              v23 = -1747789055;
              v5 = 1841140526;
            }
            else
            {
              v23 = -905888113;
              if ( !v55 )
                v23 = -1747789055;
            }
          }
          for ( mm = -1266069283; mm != 1117343424; mm = 1117343424 )
            ;
          LODWORD(v4) = -1857506287;
        }
      }
      if ( (_DWORD)v4 != -2044314777 )
        break;
      v52 = &v65;
      LOBYTE(v54) = v65;
      v33 = -2068181318;
      while ( 1 )
      {
        while ( 1 )
        {
          while ( v33 > -815281630 )
          {
            if ( v33 > 1046830677 )
            {
              if ( v33 == 1046830678 )
              {
                *(_BYTE *)v50 = (_BYTE)v49;
                v56 = v55 + 1;
                v33 = -815281629;
              }
              else
              {
                v51 = &v55;
                v55 = 0;
                v33 = -291708896;
              }
            }
            else if ( v33 == -815281629 )
            {
              v55 = v56;
              v33 = -291708896;
            }
            else
            {
              v33 = -1709579335;
              if ( v55 < 0x33 )
                v33 = -1597250588;
            }
          }
          if ( v33 <= -1709579336 )
            break;
          if ( v33 == -1709579335 )
          {
            v67[0] = 0;
            v67[1] = 0;
            *v52 = 0;
            v33 = -1744082920;
          }
          else
          {
            LOBYTE(v49) = v66[0] ^ v66[v55 + 1] ^ (v55 + 1) ^ 0x33;
            v50 = (unsigned __int64)&v66[v55 + 1];
            v33 = 1046830678;
          }
        }
        if ( v33 != -2068181318 )
          break;
        v33 = 1544713166;
        if ( ((unsigned __int8)v54 & 1) == 0 )
          v33 = -1744082920;
      }
      v34 = strcmp(s1, &v66[1]);
      v43 = &v61;
      LODWORD(v4) = -524878485;
      if ( !v34 )
        LODWORD(v4) = -1778426016;
    }
    if ( (_DWORD)v4 != -1778426016 )
      break;
    LODWORD(v4) = -994720242;
  }
  v69 = &off_7CA2830;
  if ( v75 != v77 )
    operator delete(v75);
  if ( v72 != v74 )
    operator delete(v72);
  if ( dest != (char *)&v71 + 8 )
    operator delete(dest);
  if ( v78[0] != &v79 )
    operator delete(v78[0]);
  return v47;
}


// ===== sub_56B4244 @ 0x56b4244 (size 0xebf9) =====
// bad sp value at call has been detected, the output may be wrong!
_QWORD *__fastcall sub_56B4244(_QWORD *a1)
{
  __int64 v1; // rax
  __int64 v2; // rax
  char *v3; // r14
  int i; // r15d
  int v5; // ecx
  char *v6; // rax
  int v7; // eax
  int v8; // ecx
  char *v9; // rax
  int jj; // eax
  int v11; // ecx
  char *v12; // rax
  int kk; // eax
  char *v14; // r15
  __int128 v15; // kr00_16
  __int64 v16; // rdi
  int v17; // ecx
  char *v18; // rax
  int v19; // eax
  int v20; // ecx
  char *v21; // r9
  int n; // eax
  int v23; // ecx
  char *v24; // rax
  int ii; // eax
  char *v26; // r15
  __int128 v27; // kr10_16
  __int64 v28; // rdi
  int v29; // ecx
  char *v30; // rax
  char *v31; // rax
  int j; // eax
  _BYTE *v33; // rcx
  _BYTE *v34; // rax
  int v35; // ecx
  _BYTE *v36; // rdx
  char *v37; // rax
  int k; // eax
  _BYTE *v39; // r13
  void *m; // rax
  __int64 v41; // r12
  int v42; // eax
  bool v43; // zf
  __int64 v44; // rax
  int v45; // eax
  __int64 v46; // rdx
  __int64 i3; // rcx
  int v48; // ebx
  unsigned __int64 v49; // r15
  int v50; // ecx
  _BYTE *v51; // rax
  _BYTE *v52; // rax
  int mm; // eax
  __int64 v54; // rdx
  __int64 v55; // rcx
  __int64 v56; // r8
  __int64 v57; // r9
  int nn; // eax
  _BYTE *v59; // rax
  int i41; // eax
  _BYTE *v61; // rax
  void *v62; // rax
  int v63; // eax
  __int64 v64; // rax
  __int64 v65; // rax
  int v66; // eax
  __int64 v67; // rax
  __int64 v68; // rax
  int v69; // eax
  char *v70; // r15
  time_t v71; // rax
  __int64 v72; // rbx
  int i16; // esi
  int v74; // eax
  __int64 (__fastcall **v75)(); // r15
  void *v76; // rdx
  __int64 v77; // rcx
  __int64 v78; // r8
  __int64 v79; // r9
  int v80; // eax
  void *v81; // rbx
  int v82; // eax
  int i19; // eax
  int v84; // r13d
  int i20; // eax
  int v86; // ecx
  int v87; // eax
  int i21; // eax
  int v89; // r13d
  int i22; // eax
  int v91; // ecx
  __int64 v92; // rax
  int v93; // ecx
  char *v94; // rax
  int v95; // eax
  int v96; // ecx
  char *v97; // rax
  unsigned __int64 v98; // rbx
  char *v99; // rax
  char *v100; // rax
  int i17; // eax
  char *v102; // rax
  int i23; // eax
  int v104; // ecx
  __int8 *v105; // rax
  int i18; // eax
  int i24; // eax
  int i25; // eax
  char *v109; // rax
  int i26; // eax
  int v111; // ecx
  char *v112; // rax
  int i27; // eax
  int v114; // ecx
  char *v115; // rax
  char *v116; // rax
  _BYTE *v117; // rbx
  __int64 v118; // rax
  _BYTE *v119; // rdx
  int v120; // eax
  __int64 v121; // rbx
  _BYTE *v122; // r15
  __int64 v123; // rax
  void *v124; // rbx
  unsigned int v125; // r15d
  _BYTE *v126; // rcx
  _BYTE *v127; // rax
  int v128; // ecx
  _BYTE *v129; // rax
  char *v130; // rdx
  int i15; // ecx
  _BYTE *v132; // rax
  _BYTE *v133; // rcx
  int v134; // eax
  _BYTE *v135; // rax
  time_t v136; // rax
  int v137; // eax
  time_t v138; // rax
  __int64 v139; // rbx
  int i2; // esi
  int v141; // eax
  void *v142; // r14
  char *v143; // r13
  void *v144; // rdx
  __int64 v145; // rcx
  __int64 v146; // r8
  __int64 v147; // r9
  int v148; // eax
  void *v149; // rbx
  int v150; // eax
  int i6; // eax
  int i7; // eax
  int v153; // ecx
  int v154; // eax
  int i8; // eax
  int i9; // eax
  int v157; // ecx
  __int64 v158; // rax
  int v159; // ecx
  char *v160; // rax
  int v161; // eax
  int v162; // ecx
  char *v163; // rax
  unsigned __int64 v164; // rbx
  char *v165; // rax
  char *v166; // rax
  int i4; // eax
  char *v168; // rax
  int i10; // eax
  int v170; // ecx
  __int8 *v171; // rax
  int i5; // eax
  int i11; // eax
  int i12; // eax
  char *v175; // rax
  int i13; // eax
  int v177; // ecx
  char *v178; // rax
  int i14; // eax
  int v180; // ecx
  char *v181; // rax
  char *v182; // rax
  _BYTE *v183; // rbx
  __int64 v184; // rax
  _BYTE *v185; // rdx
  __int64 v186; // r14
  int v187; // eax
  __int64 v188; // rbx
  _BYTE *v189; // r15
  __int64 v190; // rax
  void *v191; // rbx
  _BYTE *v192; // rcx
  _BYTE *v193; // rax
  int v194; // ecx
  _BYTE *v195; // rax
  char *v196; // rdx
  int i1; // ecx
  _BYTE *v198; // rax
  _BYTE *v199; // rcx
  int v200; // eax
  _BYTE *v201; // rax
  time_t v202; // rax
  int v203; // eax
  char *v204; // r15
  time_t v205; // rax
  __int64 v206; // rbx
  int i29; // esi
  int v208; // eax
  __int64 (__fastcall **v209)(); // r15
  void *v210; // rdx
  __int64 v211; // rcx
  __int64 v212; // r8
  __int64 v213; // r9
  int v214; // eax
  void *v215; // rbx
  int v216; // eax
  int i32; // eax
  int v218; // r13d
  int i33; // eax
  int v220; // ecx
  int v221; // eax
  int i34; // eax
  int v223; // r13d
  int i35; // eax
  int v225; // ecx
  __int64 v226; // rax
  int v227; // ecx
  char *v228; // rax
  int v229; // eax
  int v230; // ecx
  char *v231; // rax
  unsigned __int64 v232; // rbx
  char *v233; // rax
  char *v234; // rax
  int i30; // eax
  char *v236; // rax
  int i36; // eax
  int v238; // ecx
  __int8 *v239; // rax
  int i31; // eax
  int i37; // eax
  int i38; // eax
  char *v243; // rax
  int i39; // eax
  int v245; // ecx
  char *v246; // rax
  int i40; // eax
  int v248; // ecx
  char *v249; // rax
  char *v250; // rax
  _BYTE *v251; // rbx
  __int64 v252; // rax
  _BYTE *v253; // rdx
  int v254; // eax
  __int64 v255; // rbx
  _BYTE *v256; // r15
  __int64 v257; // rax
  void *v258; // rbx
  unsigned int v259; // r15d
  _BYTE *v260; // rcx
  _BYTE *v261; // rax
  int v262; // ecx
  _BYTE *v263; // rax
  char *v264; // rdx
  int i28; // ecx
  _BYTE *v266; // rax
  _BYTE *v267; // rcx
  int v268; // eax
  _BYTE *v269; // rax
  time_t v270; // rax
  void **v271; // rdx
  _OWORD *v272; // rax
  _BYTE *v274; // [rsp+0h] [rbp-760h] BYREF
  __int64 v275; // [rsp+8h] [rbp-758h]
  __int64 *v276; // [rsp+10h] [rbp-750h]
  char *v277; // [rsp+18h] [rbp-748h]
  __int64 *v278; // [rsp+20h] [rbp-740h]
  __int64 v279; // [rsp+28h] [rbp-738h]
  time_t v280; // [rsp+30h] [rbp-730h]
  char *v281; // [rsp+38h] [rbp-728h]
  char *v282; // [rsp+40h] [rbp-720h]
  _BYTE *v283; // [rsp+48h] [rbp-718h]
  __int64 *v284; // [rsp+50h] [rbp-710h]
  _QWORD *v285; // [rsp+58h] [rbp-708h]
  __int64 *v286; // [rsp+60h] [rbp-700h]
  __int64 *v287; // [rsp+68h] [rbp-6F8h]
  _BYTE *v288; // [rsp+70h] [rbp-6F0h]
  _BYTE **v289; // [rsp+78h] [rbp-6E8h]
  _DWORD *v290; // [rsp+80h] [rbp-6E0h]
  _QWORD **v291; // [rsp+88h] [rbp-6D8h]
  __int64 *v292; // [rsp+90h] [rbp-6D0h]
  char *v293; // [rsp+98h] [rbp-6C8h]
  __int64 *v294; // [rsp+A0h] [rbp-6C0h]
  __int64 *v295; // [rsp+A8h] [rbp-6B8h]
  _BYTE *v296; // [rsp+B0h] [rbp-6B0h]
  _QWORD *v297; // [rsp+B8h] [rbp-6A8h]
  char *v298; // [rsp+C0h] [rbp-6A0h]
  char *v299; // [rsp+C8h] [rbp-698h]
  char *v300; // [rsp+D0h] [rbp-690h]
  char *v301; // [rsp+D8h] [rbp-688h]
  char *v302; // [rsp+E0h] [rbp-680h]
  time_t v303; // [rsp+E8h] [rbp-678h]
  _BYTE *v304; // [rsp+F0h] [rbp-670h]
  unsigned __int64 v305; // [rsp+F8h] [rbp-668h]
  pthread_mutex_t *v306; // [rsp+100h] [rbp-660h]
  _BYTE *v307; // [rsp+108h] [rbp-658h]
  __int64 v308; // [rsp+110h] [rbp-650h]
  _QWORD *v309; // [rsp+118h] [rbp-648h]
  pthread_mutex_t *v310; // [rsp+120h] [rbp-640h]
  _QWORD *v311; // [rsp+128h] [rbp-638h]
  _DWORD *v312; // [rsp+130h] [rbp-630h]
  __int64 v313; // [rsp+138h] [rbp-628h]
  _QWORD *v314; // [rsp+140h] [rbp-620h]
  _QWORD *v315; // [rsp+148h] [rbp-618h]
  _DWORD *v316; // [rsp+150h] [rbp-610h]
  __int64 *v317; // [rsp+158h] [rbp-608h]
  _OWORD *v318; // [rsp+160h] [rbp-600h]
  __int64 *v319; // [rsp+168h] [rbp-5F8h]
  __int64 *v320; // [rsp+170h] [rbp-5F0h]
  unsigned __int64 *v321; // [rsp+178h] [rbp-5E8h]
  void **v322; // [rsp+180h] [rbp-5E0h]
  unsigned __int64 *v323; // [rsp+188h] [rbp-5D8h]
  unsigned __int64 *v324; // [rsp+190h] [rbp-5D0h]
  void **v325; // [rsp+198h] [rbp-5C8h]
  _QWORD *v326; // [rsp+1A0h] [rbp-5C0h]
  _BYTE *v327; // [rsp+1A8h] [rbp-5B8h]
  _BYTE *v328; // [rsp+1B0h] [rbp-5B0h]
  pthread_mutex_t **v329; // [rsp+1B8h] [rbp-5A8h]
  _BYTE *v330; // [rsp+1C0h] [rbp-5A0h]
  unsigned __int64 *v331; // [rsp+1C8h] [rbp-598h]
  __int32 v332; // [rsp+1D4h] [rbp-58Ch]
  _BYTE *v333; // [rsp+1D8h] [rbp-588h]
  _BYTE *v334; // [rsp+1E0h] [rbp-580h]
  _BYTE *v335; // [rsp+1E8h] [rbp-578h]
  _BYTE *v336; // [rsp+1F0h] [rbp-570h]
  bool v337; // [rsp+1FFh] [rbp-561h]
  _QWORD *v338; // [rsp+200h] [rbp-560h]
  int v339; // [rsp+20Ch] [rbp-554h]
  void **v340; // [rsp+210h] [rbp-550h]
  char *v341; // [rsp+218h] [rbp-548h]
  bool v342; // [rsp+226h] [rbp-53Ah]
  bool v343; // [rsp+227h] [rbp-539h]
  char *v344; // [rsp+228h] [rbp-538h]
  unsigned __int64 v345; // [rsp+230h] [rbp-530h]
  char v346; // [rsp+23Fh] [rbp-521h]
  _QWORD *v347; // [rsp+240h] [rbp-520h] BYREF
  pthread_mutex_t *v348; // [rsp+248h] [rbp-518h] BYREF
  unsigned __int64 v349; // [rsp+250h] [rbp-510h] BYREF
  char v350; // [rsp+258h] [rbp-508h] BYREF
  __int64 v351; // [rsp+260h] [rbp-500h]
  __int64 v352; // [rsp+268h] [rbp-4F8h]
  __int64 v353; // [rsp+278h] [rbp-4E8h]
  unsigned __int64 v354; // [rsp+280h] [rbp-4E0h] BYREF
  int v355; // [rsp+288h] [rbp-4D8h] BYREF
  __int64 v356; // [rsp+290h] [rbp-4D0h]
  int *v357; // [rsp+298h] [rbp-4C8h]
  int *v358; // [rsp+2A0h] [rbp-4C0h]
  __int64 v359; // [rsp+2A8h] [rbp-4B8h]
  __int64 v360; // [rsp+2B0h] [rbp-4B0h] BYREF
  __int64 v361; // [rsp+2B8h] [rbp-4A8h] BYREF
  void **v362; // [rsp+2C0h] [rbp-4A0h] BYREF
  pthread_mutex_t *mutex; // [rsp+2C8h] [rbp-498h] BYREF
  pthread_mutex_t **p_mutex; // [rsp+2D0h] [rbp-490h] BYREF
  char *v365; // [rsp+2D8h] [rbp-488h] BYREF
  unsigned __int64 v366; // [rsp+2E0h] [rbp-480h] BYREF
  unsigned __int64 v367; // [rsp+2E8h] [rbp-478h] BYREF
  void *v368[2]; // [rsp+2F0h] [rbp-470h] BYREF
  _BYTE v369[16]; // [rsp+300h] [rbp-460h] BYREF
  void *v370; // [rsp+310h] [rbp-450h] BYREF
  void *v371; // [rsp+318h] [rbp-448h]
  __int128 v372; // [rsp+320h] [rbp-440h] BYREF
  void *v373[2]; // [rsp+330h] [rbp-430h] BYREF
  char v374; // [rsp+340h] [rbp-420h] BYREF
  __int64 v375; // [rsp+350h] [rbp-410h] BYREF
  _BYTE v376[9]; // [rsp+358h] [rbp-408h] BYREF
  _BYTE v377[2]; // [rsp+361h] [rbp-3FFh] BYREF
  char v378; // [rsp+363h] [rbp-3FDh] BYREF
  __int64 v379; // [rsp+368h] [rbp-3F8h] BYREF
  char v380; // [rsp+370h] [rbp-3F0h]
  char v381; // [rsp+371h] [rbp-3EFh]
  char v382; // [rsp+372h] [rbp-3EEh]
  char v383; // [rsp+373h] [rbp-3EDh]
  char v384; // [rsp+374h] [rbp-3ECh]
  char v385; // [rsp+375h] [rbp-3EBh]
  char v386; // [rsp+376h] [rbp-3EAh]
  _BYTE v387[8]; // [rsp+377h] [rbp-3E9h] BYREF
  char v388; // [rsp+37Fh] [rbp-3E1h] BYREF
  char v389; // [rsp+380h] [rbp-3E0h]
  _BYTE v390[11]; // [rsp+381h] [rbp-3DFh] BYREF
  _BYTE v391[5]; // [rsp+38Ch] [rbp-3D4h] BYREF
  _BYTE v392[35]; // [rsp+391h] [rbp-3CFh] BYREF
  _BYTE v393[14]; // [rsp+3B4h] [rbp-3ACh] BYREF
  _BYTE v394[2]; // [rsp+3C2h] [rbp-39Eh] BYREF
  char v395; // [rsp+3C4h] [rbp-39Ch] BYREF
  _BYTE *v396; // [rsp+3C8h] [rbp-398h] BYREF
  void *v397[2]; // [rsp+3D0h] [rbp-390h] BYREF
  _BYTE v398[16]; // [rsp+3E0h] [rbp-380h] BYREF
  __int64 v399; // [rsp+3F0h] [rbp-370h] BYREF
  char v400; // [rsp+3F8h] [rbp-368h]
  char v401; // [rsp+3F9h] [rbp-367h]
  char v402; // [rsp+3FAh] [rbp-366h]
  char v403; // [rsp+3FBh] [rbp-365h]
  char v404; // [rsp+3FCh] [rbp-364h]
  char v405; // [rsp+3FDh] [rbp-363h]
  char v406; // [rsp+3FEh] [rbp-362h]
  char v407; // [rsp+3FFh] [rbp-361h]
  char v408; // [rsp+400h] [rbp-360h]
  char v409; // [rsp+401h] [rbp-35Fh]
  char v410; // [rsp+402h] [rbp-35Eh]
  char v411; // [rsp+403h] [rbp-35Dh]
  char v412; // [rsp+404h] [rbp-35Ch]
  _BYTE v413[5]; // [rsp+405h] [rbp-35Bh] BYREF
  _BYTE v414[2]; // [rsp+40Ah] [rbp-356h] BYREF
  char v415; // [rsp+40Ch] [rbp-354h] BYREF
  char v416; // [rsp+410h] [rbp-350h] BYREF
  char v417; // [rsp+411h] [rbp-34Fh]
  char v418; // [rsp+412h] [rbp-34Eh] BYREF
  char v419; // [rsp+413h] [rbp-34Dh]
  char v420; // [rsp+414h] [rbp-34Ch]
  char v421; // [rsp+415h] [rbp-34Bh]
  char v422; // [rsp+416h] [rbp-34Ah]
  char v423; // [rsp+417h] [rbp-349h]
  char v424; // [rsp+418h] [rbp-348h]
  char v425; // [rsp+419h] [rbp-347h]
  char v426; // [rsp+41Ah] [rbp-346h]
  char v427; // [rsp+41Bh] [rbp-345h]
  char v428; // [rsp+41Ch] [rbp-344h]
  char v429; // [rsp+41Dh] [rbp-343h]
  char v430; // [rsp+41Eh] [rbp-342h]
  char v431; // [rsp+41Fh] [rbp-341h]
  char v432; // [rsp+420h] [rbp-340h]
  char v433; // [rsp+421h] [rbp-33Fh]
  char v434; // [rsp+422h] [rbp-33Eh]
  char v435; // [rsp+423h] [rbp-33Dh]
  char v436; // [rsp+424h] [rbp-33Ch]
  char v437; // [rsp+425h] [rbp-33Bh]
  char v438; // [rsp+426h] [rbp-33Ah]
  char v439; // [rsp+427h] [rbp-339h]
  _BYTE v440[5]; // [rsp+428h] [rbp-338h] BYREF
  char v441; // [rsp+42Dh] [rbp-333h] BYREF
  char v442; // [rsp+42Eh] [rbp-332h]
  _BYTE v443[5]; // [rsp+42Fh] [rbp-331h] BYREF
  _BYTE v444[5]; // [rsp+434h] [rbp-32Ch] BYREF
  _BYTE v445[35]; // [rsp+439h] [rbp-327h] BYREF
  _BYTE v446[14]; // [rsp+45Ch] [rbp-304h] BYREF
  _BYTE v447[2]; // [rsp+46Ah] [rbp-2F6h] BYREF
  char v448; // [rsp+46Ch] [rbp-2F4h] BYREF
  _OWORD nptr[2]; // [rsp+470h] [rbp-2F0h] BYREF
  void *v450; // [rsp+490h] [rbp-2D0h] BYREF
  __int64 v451; // [rsp+498h] [rbp-2C8h]
  _BYTE v452[16]; // [rsp+4A0h] [rbp-2C0h] BYREF
  void *v453; // [rsp+4B0h] [rbp-2B0h]
  char v454; // [rsp+4B8h] [rbp-2A8h]
  char v455; // [rsp+4B9h] [rbp-2A7h]
  char v456; // [rsp+4BAh] [rbp-2A6h]
  char v457; // [rsp+4BBh] [rbp-2A5h]
  _BYTE v458[12]; // [rsp+4BCh] [rbp-2A4h] BYREF
  char v459; // [rsp+4C8h] [rbp-298h]
  char v460; // [rsp+4C9h] [rbp-297h]
  char v461; // [rsp+4CAh] [rbp-296h] BYREF
  char v462; // [rsp+4CBh] [rbp-295h]
  _BYTE v463[4]; // [rsp+4CCh] [rbp-294h] BYREF
  void *v464; // [rsp+4D0h] [rbp-290h]
  _BYTE v465[16]; // [rsp+4E0h] [rbp-280h] BYREF
  void *v466; // [rsp+4F0h] [rbp-270h]
  __int64 v467; // [rsp+500h] [rbp-260h] BYREF
  void *v468; // [rsp+510h] [rbp-250h]
  __int64 v469; // [rsp+520h] [rbp-240h] BYREF
  void *v470; // [rsp+530h] [rbp-230h] BYREF
  __int64 v471; // [rsp+538h] [rbp-228h]
  _BYTE v472[16]; // [rsp+540h] [rbp-220h] BYREF
  __int64 v473; // [rsp+550h] [rbp-210h] BYREF
  char v474; // [rsp+558h] [rbp-208h]
  char v475; // [rsp+559h] [rbp-207h]
  char v476; // [rsp+55Ah] [rbp-206h]
  char v477; // [rsp+55Bh] [rbp-205h]
  _BYTE v478[10]; // [rsp+55Ch] [rbp-204h] BYREF
  char v479; // [rsp+566h] [rbp-1FAh]
  char v480; // [rsp+567h] [rbp-1F9h]
  char v481; // [rsp+568h] [rbp-1F8h]
  char v482; // [rsp+569h] [rbp-1F7h] BYREF
  char v483; // [rsp+56Ah] [rbp-1F6h]
  _BYTE v484[5]; // [rsp+56Bh] [rbp-1F5h] BYREF
  unsigned __int64 v485; // [rsp+570h] [rbp-1F0h] BYREF
  char v486; // [rsp+578h] [rbp-1E8h]
  char v487; // [rsp+579h] [rbp-1E7h]
  char v488; // [rsp+57Ah] [rbp-1E6h]
  char v489; // [rsp+57Bh] [rbp-1E5h]
  char v490; // [rsp+57Ch] [rbp-1E4h]
  char v491; // [rsp+57Dh] [rbp-1E3h]
  char v492; // [rsp+57Eh] [rbp-1E2h]
  char v493; // [rsp+57Fh] [rbp-1E1h]
  char v494; // [rsp+580h] [rbp-1E0h]
  char v495; // [rsp+581h] [rbp-1DFh]
  char v496; // [rsp+582h] [rbp-1DEh]
  char v497; // [rsp+583h] [rbp-1DDh]
  char v498; // [rsp+584h] [rbp-1DCh]
  char v499; // [rsp+585h] [rbp-1DBh]
  char v500; // [rsp+586h] [rbp-1DAh]
  char v501; // [rsp+587h] [rbp-1D9h]
  char v502; // [rsp+588h] [rbp-1D8h]
  char v503; // [rsp+589h] [rbp-1D7h]
  char v504; // [rsp+58Ah] [rbp-1D6h]
  char v505; // [rsp+58Bh] [rbp-1D5h]
  char v506; // [rsp+58Ch] [rbp-1D4h]
  char v507; // [rsp+58Dh] [rbp-1D3h]
  char v508; // [rsp+58Eh] [rbp-1D2h]
  char v509; // [rsp+58Fh] [rbp-1D1h]
  char v510; // [rsp+590h] [rbp-1D0h]
  char v511; // [rsp+591h] [rbp-1CFh]
  char v512; // [rsp+592h] [rbp-1CEh]
  char v513; // [rsp+593h] [rbp-1CDh]
  _BYTE v514[4]; // [rsp+594h] [rbp-1CCh] BYREF
  char v515; // [rsp+598h] [rbp-1C8h]
  _BYTE v516[26]; // [rsp+599h] [rbp-1C7h] BYREF
  char v517; // [rsp+5B3h] [rbp-1ADh]
  char v518; // [rsp+5B4h] [rbp-1ACh]
  char v519; // [rsp+5B5h] [rbp-1ABh]
  char v520; // [rsp+5B6h] [rbp-1AAh]
  char v521; // [rsp+5B7h] [rbp-1A9h]
  char v522; // [rsp+5B8h] [rbp-1A8h]
  char v523; // [rsp+5B9h] [rbp-1A7h]
  char v524; // [rsp+5BAh] [rbp-1A6h]
  char v525; // [rsp+5BBh] [rbp-1A5h]
  _BYTE v526[12]; // [rsp+5BCh] [rbp-1A4h] BYREF
  char v527; // [rsp+5C8h] [rbp-198h]
  char v528; // [rsp+5C9h] [rbp-197h]
  char v529; // [rsp+5CAh] [rbp-196h] BYREF
  char v530; // [rsp+5CBh] [rbp-195h]
  _BYTE v531[4]; // [rsp+5CCh] [rbp-194h] BYREF
  void *v532; // [rsp+5D0h] [rbp-190h] BYREF
  __int64 v533; // [rsp+5D8h] [rbp-188h]
  _BYTE v534[16]; // [rsp+5E0h] [rbp-180h] BYREF
  unsigned __int64 v535; // [rsp+5F0h] [rbp-170h] BYREF
  _BYTE v536[28]; // [rsp+5F8h] [rbp-168h] BYREF
  char v537; // [rsp+614h] [rbp-14Ch]
  char v538; // [rsp+615h] [rbp-14Bh]
  char v539; // [rsp+616h] [rbp-14Ah]
  char v540; // [rsp+617h] [rbp-149h]
  _BYTE v541[4]; // [rsp+618h] [rbp-148h] BYREF
  char v542; // [rsp+61Ch] [rbp-144h] BYREF
  char v543; // [rsp+61Dh] [rbp-143h]
  _BYTE v544[2]; // [rsp+61Eh] [rbp-142h] BYREF
  void *v545; // [rsp+620h] [rbp-140h] BYREF
  char v546; // [rsp+628h] [rbp-138h]
  char v547; // [rsp+629h] [rbp-137h]
  char v548; // [rsp+62Ah] [rbp-136h]
  char v549; // [rsp+62Bh] [rbp-135h]
  char v550; // [rsp+62Ch] [rbp-134h]
  char v551; // [rsp+62Dh] [rbp-133h]
  char v552; // [rsp+62Eh] [rbp-132h]
  char v553; // [rsp+62Fh] [rbp-131h]
  char v554; // [rsp+630h] [rbp-130h] BYREF
  char v555; // [rsp+631h] [rbp-12Fh]
  char v556; // [rsp+632h] [rbp-12Eh]
  char v557; // [rsp+633h] [rbp-12Dh]
  char v558; // [rsp+634h] [rbp-12Ch]
  char v559; // [rsp+635h] [rbp-12Bh]
  char v560; // [rsp+636h] [rbp-12Ah]
  char v561; // [rsp+637h] [rbp-129h]
  char v562; // [rsp+638h] [rbp-128h]
  char v563; // [rsp+639h] [rbp-127h]
  char v564; // [rsp+63Ah] [rbp-126h]
  char v565; // [rsp+63Bh] [rbp-125h]
  char v566; // [rsp+63Ch] [rbp-124h]
  char v567; // [rsp+63Dh] [rbp-123h]
  char v568; // [rsp+63Eh] [rbp-122h]
  char v569; // [rsp+63Fh] [rbp-121h]
  char v570; // [rsp+640h] [rbp-120h]
  char v571; // [rsp+641h] [rbp-11Fh]
  char v572; // [rsp+642h] [rbp-11Eh]
  char v573; // [rsp+643h] [rbp-11Dh]
  _BYTE v574[4]; // [rsp+644h] [rbp-11Ch] BYREF
  char v575; // [rsp+648h] [rbp-118h]
  _BYTE v576[26]; // [rsp+649h] [rbp-117h] BYREF
  char v577; // [rsp+663h] [rbp-FDh]
  char v578; // [rsp+664h] [rbp-FCh]
  char v579; // [rsp+665h] [rbp-FBh]
  char v580; // [rsp+666h] [rbp-FAh]
  char v581; // [rsp+667h] [rbp-F9h]
  char v582; // [rsp+668h] [rbp-F8h]
  char v583; // [rsp+669h] [rbp-F7h]
  char v584; // [rsp+66Ah] [rbp-F6h]
  char v585; // [rsp+66Bh] [rbp-F5h]
  _BYTE v586[12]; // [rsp+66Ch] [rbp-F4h] BYREF
  char v587; // [rsp+678h] [rbp-E8h]
  char v588; // [rsp+679h] [rbp-E7h]
  char v589; // [rsp+67Ah] [rbp-E6h] BYREF
  char v590; // [rsp+67Bh] [rbp-E5h]
  _BYTE v591[4]; // [rsp+67Ch] [rbp-E4h] BYREF
  void *v592[2]; // [rsp+680h] [rbp-E0h] BYREF
  _BYTE v593[16]; // [rsp+690h] [rbp-D0h] BYREF
  __int64 v594; // [rsp+6A0h] [rbp-C0h] BYREF
  _BYTE v595[11]; // [rsp+6A8h] [rbp-B8h] BYREF
  char v596; // [rsp+6B3h] [rbp-ADh]
  char v597; // [rsp+6B4h] [rbp-ACh]
  char v598; // [rsp+6B5h] [rbp-ABh]
  char v599; // [rsp+6B6h] [rbp-AAh]
  char v600; // [rsp+6B7h] [rbp-A9h]
  char v601; // [rsp+6B8h] [rbp-A8h]
  char v602; // [rsp+6B9h] [rbp-A7h]
  char v603; // [rsp+6BAh] [rbp-A6h]
  char v604; // [rsp+6BBh] [rbp-A5h]
  char v605; // [rsp+6BCh] [rbp-A4h]
  char v606; // [rsp+6BDh] [rbp-A3h] BYREF
  char v607; // [rsp+6BEh] [rbp-A2h]
  char v608; // [rsp+6BFh] [rbp-A1h] BYREF
  void *v609; // [rsp+6C0h] [rbp-A0h] BYREF
  __int64 v610; // [rsp+6C8h] [rbp-98h]
  __int128 v611; // [rsp+6D0h] [rbp-90h] BYREF
  unsigned __int64 v612; // [rsp+6E0h] [rbp-80h] BYREF
  __m256i v613; // [rsp+6E8h] [rbp-78h] BYREF
  char v614; // [rsp+708h] [rbp-58h]
  _BYTE v615[7]; // [rsp+709h] [rbp-57h] BYREF
  void *v616; // [rsp+710h] [rbp-50h] BYREF
  __int64 (__fastcall **v617)(); // [rsp+718h] [rbp-48h] BYREF
  char v618; // [rsp+720h] [rbp-40h] BYREF
  _QWORD v619[2]; // [rsp+728h] [rbp-38h] BYREF
  _QWORD v620[5]; // [rsp+738h] [rbp-28h] BYREF

  v297 = a1;
  v619[1] = __readfsqword(0x28u);
  v1 = sub_56C2E3E();
  sub_56957EC(v373, *(_QWORD *)(v1 + 96), nptr);
  v2 = sub_56C2F24();
  v285 = &v274;
  v315 = &v274;
  v308 = v2 + 144;
  v330 = (_BYTE *)(v2 + 176);
  v314 = (_QWORD *)(v2 + 248);
  v309 = (_QWORD *)(v2 + 112);
  v3 = (char *)&v545 + 2;
  v344 = (char *)v2;
  v310 = (pthread_mutex_t *)(v2 + 192);
  for ( i = 438638509; ; i = -1191111182 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
LABEL_2:
        while ( i <= 438638508 )
        {
          if ( i > -110330528 )
          {
            if ( i <= 296083443 )
            {
              if ( i == -110330527 )
              {
                v416 = 1;
                v417 = 47;
                v418 = 82;
                v419 = 83;
                v420 = 67;
                v421 = 104;
                v422 = 70;
                v423 = 123;
                v424 = 87;
                v425 = 28;
                v426 = 95;
                v427 = 75;
                v428 = 75;
                v429 = 24;
                v430 = 74;
                v431 = 77;
                v432 = 82;
                v433 = 80;
                v434 = 70;
                v435 = 78;
                v436 = 7;
                v437 = 73;
                v438 = 82;
                v439 = 2;
                qmemcpy(v440, "@@B]J", sizeof(v440));
                *(_QWORD *)&nptr[0] = v443;
                v29 = -769038311;
                v30 = &v441;
                while ( v29 != 1284930719 )
                {
                  *v30++ = 0;
                  v29 = -769038311;
                  if ( v30 == *(char **)&nptr[0] )
                    v29 = 1284930719;
                }
                v612 = (unsigned __int64)&v416;
                LOBYTE(v535) = v416;
                LODWORD(v31) = -962714612;
                do
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( (int)v31 > -324670996 )
                      {
                        if ( (int)v31 > 307205468 )
                        {
                          if ( (_DWORD)v31 == 307205469 )
                          {
                            LODWORD(v349) = v354;
                            LODWORD(v31) = -324670995;
                          }
                          else if ( (_DWORD)v31 == 834103254 )
                          {
                            v441 = 0;
                            v442 = 0;
                            *(_BYTE *)v612 = 0;
                            LODWORD(v31) = -1997885474;
                          }
                        }
                        else if ( (_DWORD)v31 == -324670995 )
                        {
                          *(&v418 + v354) ^= (v349 + 1) ^ v417 ^ 0x1B;
                          *(_QWORD *)&nptr[0] = v354 + 1;
                          v31 = byte_28E9C53;
                        }
                        else if ( (_DWORD)v31 == (_DWORD)byte_28E9C53 )
                        {
                          v354 = *(_QWORD *)&nptr[0];
                          LODWORD(v31) = -794593716;
                        }
                      }
                      if ( (int)v31 <= -962714613 )
                        break;
                      if ( (_DWORD)v31 == -962714612 )
                      {
                        LODWORD(v31) = -2083131433;
                        if ( (v535 & 1) == 0 )
                          LODWORD(v31) = -1997885474;
                      }
                      else if ( (_DWORD)v31 == -794593716 )
                      {
                        LODWORD(v31) = 834103254;
                        if ( v354 < 0x1B )
                          LODWORD(v31) = 307205469;
                      }
                    }
                    if ( (_DWORD)v31 != -2083131433 )
                      break;
                    v379 = (__int64)&v354;
                    v354 = 0;
                    LODWORD(v31) = -794593716;
                  }
                }
                while ( (_DWORD)v31 != -1997885474 );
                sub_56A4A43(v341, 318, &v418, "[FGESDK]", 1);
                i = 381741052;
                v3 = (char *)&v545 + 2;
              }
              else
              {
                v473 = *(_QWORD *)v375;
                i = -987152676;
              }
            }
            else if ( i == 296083444 )
            {
              v612 = (unsigned __int64)&v485;
              LOBYTE(v535) = v485;
              for ( j = -675995946; ; j = 740258254 )
              {
                while ( 1 )
                {
                  while ( j > 673470317 )
                  {
                    if ( j > 810545848 )
                    {
                      if ( j == 810545849 )
                      {
                        ++v354;
                      }
                      else
                      {
                        v379 = (__int64)&v354;
                        v354 = 0;
                      }
                      j = -495751738;
                    }
                    else if ( j == 673470318 )
                    {
                      v529 = 0;
                      v530 = 0;
                      *(_BYTE *)v612 = 0;
                      j = -958661634;
                    }
                    else
                    {
                      **(_BYTE **)&nptr[0] = v349;
                      j = 810545849;
                    }
                  }
                  if ( j <= -675995947 )
                    break;
                  if ( j == -675995946 )
                  {
                    j = 1310473308;
                    if ( (v535 & 1) == 0 )
                      j = -958661634;
                  }
                  else
                  {
                    j = 673470318;
                    if ( v354 < 0x58 )
                      j = -2012962271;
                  }
                }
                if ( j != -2012962271 )
                  break;
                LOBYTE(v349) = BYTE1(v485) ^ *((_BYTE *)&v485 + v354 + 2) ^ (v354 + 1) ^ 0x58;
                *(_QWORD *)&nptr[0] = (char *)&v485 + v354 + 2;
              }
              v33 = v338;
              *(_BYTE *)v338 = 1;
              v33[1] = 47;
              v33[2] = 82;
              v33[3] = 83;
              v33[4] = 67;
              v33[5] = 104;
              v33[6] = 70;
              v33[7] = 123;
              v33[8] = 87;
              v33[9] = 28;
              v33[10] = 95;
              v33[11] = 75;
              v33[12] = 75;
              v33[13] = 24;
              v33[14] = 84;
              v33[15] = 126;
              v33[16] = 94;
              v33[17] = 82;
              v33[18] = 76;
              v33[19] = 69;
              v33[20] = 66;
              v33[21] = 0;
              v33[22] = 72;
              v33[23] = 81;
              v33[24] = 3;
              v33[25] = 66;
              v33[26] = 88;
              v33[27] = 66;
              v33[28] = 67;
              v34 = v33 + 29;
              *(_QWORD *)&nptr[0] = v33 + 31;
              v35 = -769038311;
              while ( v35 != 1284930719 )
              {
                *v34++ = 0;
                v35 = -769038311;
                if ( v34 == *(_BYTE **)&nptr[0] )
                  v35 = 1284930719;
              }
              v36 = v338;
              v612 = (unsigned __int64)v338;
              LOBYTE(v535) = *(_BYTE *)v338;
              LODWORD(v37) = -962714612;
              do
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( (int)v37 > -324670996 )
                    {
                      if ( (int)v37 > 307205468 )
                      {
                        if ( (_DWORD)v37 == 307205469 )
                        {
                          LODWORD(v349) = v354;
                          LODWORD(v37) = -324670995;
                        }
                        else if ( (_DWORD)v37 == 834103254 )
                        {
                          v36[29] = 0;
                          v36[30] = 0;
                          *(_BYTE *)v612 = 0;
                          LODWORD(v37) = -1997885474;
                        }
                      }
                      else if ( (_DWORD)v37 == -324670995 )
                      {
                        v36[v354 + 2] ^= (v349 + 1) ^ v36[1] ^ 0x1B;
                        *(_QWORD *)&nptr[0] = v354 + 1;
                        v37 = byte_28E9C53;
                      }
                      else if ( (_DWORD)v37 == (_DWORD)byte_28E9C53 )
                      {
                        v354 = *(_QWORD *)&nptr[0];
                        LODWORD(v37) = -794593716;
                      }
                    }
                    if ( (int)v37 <= -962714613 )
                      break;
                    if ( (_DWORD)v37 == -962714612 )
                    {
                      LODWORD(v37) = -2083131433;
                      if ( (v535 & 1) == 0 )
                        LODWORD(v37) = -1997885474;
                    }
                    else if ( (_DWORD)v37 == -794593716 )
                    {
                      LODWORD(v37) = 834103254;
                      if ( v354 < 0x1B )
                        LODWORD(v37) = 307205469;
                    }
                  }
                  if ( (_DWORD)v37 != -2083131433 )
                    break;
                  v379 = (__int64)&v354;
                  v354 = 0;
                  LODWORD(v37) = -794593716;
                }
              }
              while ( (_DWORD)v37 != -1997885474 );
              sub_56A4A43((char *)&v485 + 2, 324, v36 + 2, "[FGESDK]", 2);
              i = 336292162;
              v3 = (char *)&v545 + 2;
            }
            else if ( i == 336292162 )
            {
              i = 381741052;
            }
            else
            {
              i = 1349638112;
            }
          }
          else if ( i <= -987152677 )
          {
            if ( i == -1358538699 )
            {
              i = 2077471311;
              if ( !*(_QWORD *)v344 )
                i = 1515531231;
            }
            else
            {
              v545 = (void *)0x5E061C1B07592F01LL;
              v546 = 20;
              v547 = 26;
              v548 = 8;
              v549 = 18;
              v550 = 12;
              v551 = 8;
              v552 = 85;
              v553 = 21;
              v554 = 17;
              v555 = 9;
              v556 = 19;
              v557 = 29;
              v558 = 75;
              v559 = 27;
              v560 = 84;
              v561 = 85;
              v562 = 79;
              v563 = 31;
              v564 = 2;
              v565 = 12;
              v566 = 24;
              v567 = 13;
              v568 = 5;
              v569 = 27;
              v570 = 5;
              v571 = 36;
              v572 = 121;
              v573 = 25;
              qmemcpy(v574, "==')", sizeof(v574));
              v575 = 127;
              qmemcpy(v576, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v576));
              v577 = 26;
              v578 = 93;
              v579 = 93;
              v580 = 81;
              v581 = 93;
              v582 = 69;
              v583 = 91;
              v584 = 91;
              v585 = 18;
              qmemcpy(v586, "X^LP[ByQKHGO", sizeof(v586));
              v587 = 14;
              v588 = 71;
              *(_QWORD *)&nptr[0] = v591;
              v17 = 434048087;
              v18 = &v589;
              while ( v17 != -1401140967 )
              {
                *v18++ = 0;
                v17 = 434048087;
                if ( v18 == *(char **)&nptr[0] )
                  v17 = -1401140967;
              }
              v612 = (unsigned __int64)&v545;
              LOBYTE(v535) = (_BYTE)v545;
              for ( k = -675995946; ; k = 740258254 )
              {
                while ( 1 )
                {
                  while ( k > 673470317 )
                  {
                    if ( k > 810545848 )
                    {
                      if ( k == 810545849 )
                      {
                        ++v354;
                      }
                      else
                      {
                        v379 = (__int64)&v354;
                        v354 = 0;
                      }
                      k = -495751738;
                    }
                    else if ( k == 673470318 )
                    {
                      v589 = 0;
                      v590 = 0;
                      *(_BYTE *)v612 = 0;
                      k = -958661634;
                    }
                    else
                    {
                      **(_BYTE **)&nptr[0] = v349;
                      k = 810545849;
                    }
                  }
                  if ( k <= -675995947 )
                    break;
                  if ( k == -675995946 )
                  {
                    k = 1310473308;
                    if ( (v535 & 1) == 0 )
                      k = -958661634;
                  }
                  else
                  {
                    k = 673470318;
                    if ( v354 < 0x58 )
                      k = -2012962271;
                  }
                }
                if ( k != -2012962271 )
                  break;
                LOBYTE(v349) = BYTE1(v545) ^ *((_BYTE *)&v545 + v354 + 2) ^ (v354 + 1) ^ 0x58;
                *(_QWORD *)&nptr[0] = (char *)&v545 + v354 + 2;
              }
              v341 = (char *)&v545 + 2;
              v365 = &v416;
              i = -110330527;
            }
          }
          else if ( i == -987152676 )
          {
            i = 488065354;
            if ( (__int64)v367 > v473 )
              i = -1358538699;
          }
          else
          {
            if ( i == -961197315 )
            {
              std::string::_M_assign(v368, v345);
              std::string::_M_assign(&v370, v308);
              v3 = (char *)&v545 + 2;
              goto LABEL_96;
            }
            v485 = 0x5E061C1B07592F01LL;
            v486 = 20;
            v487 = 26;
            v488 = 8;
            v489 = 18;
            v490 = 12;
            v491 = 8;
            v492 = 85;
            v493 = 21;
            v494 = 17;
            v495 = 9;
            v496 = 19;
            v497 = 29;
            v498 = 75;
            v499 = 27;
            v500 = 84;
            v501 = 85;
            v502 = 79;
            v503 = 31;
            v504 = 2;
            v505 = 12;
            v506 = 24;
            v507 = 13;
            v508 = 5;
            v509 = 27;
            v510 = 5;
            v511 = 36;
            v512 = 121;
            v513 = 25;
            qmemcpy(v514, "==')", sizeof(v514));
            v515 = 127;
            qmemcpy(v516, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v516));
            v517 = 26;
            v518 = 93;
            v519 = 93;
            v520 = 81;
            v521 = 93;
            v522 = 69;
            v523 = 91;
            v524 = 91;
            v525 = 18;
            qmemcpy(v526, "X^LP[ByQKHGO", sizeof(v526));
            v527 = 14;
            v528 = 71;
            *(_QWORD *)&nptr[0] = v531;
            v5 = 434048087;
            v6 = &v529;
            while ( v5 != -1401140967 )
            {
              *v6++ = 0;
              v5 = 434048087;
              if ( v6 == *(char **)&nptr[0] )
                v5 = -1401140967;
            }
            i = 296083444;
          }
        }
        if ( i <= 1538019840 )
          break;
        if ( i <= 1837498013 )
        {
          if ( i != 1538019841 )
          {
            v367 = v366 - *((_QWORD *)v344 + 23);
            v375 = (__int64)v314;
            i = 271433117;
            continue;
          }
          mutex = v310;
          sub_56E5AFC(v310);
          v368[0] = v369;
          v368[1] = 0;
          v369[0] = 0;
          v370 = &v372;
          v371 = 0;
          LOBYTE(v372) = 0;
          v39 = (_BYTE *)sub_56CE9EA();
          v307 = &v274;
          v336 = v39 + 160;
          v312 = v39 + 4;
          for ( m = &loc_717BD84; ; LODWORD(m) = -882590125 )
          {
            while ( 1 )
            {
LABEL_268:
              if ( (int)m > -46331659 )
              {
                if ( (int)m > 285114297 )
                {
                  if ( (_DWORD)m == 285114298 )
                  {
                    LODWORD(m) = -998981451;
                    continue;
                  }
                  if ( (_DWORD)m != 425873861 )
                  {
                    if ( (_DWORD)m == 1516859029 )
                    {
                      LODWORD(m) = atoi(*(const char **)&nptr[0]);
                      *(_DWORD *)v532 = (_DWORD)m;
                      v43 = (_DWORD)m == -1;
                      LODWORD(m) = -1030155360;
                      if ( v43 )
                        LODWORD(m) = 425873861;
                    }
                    continue;
                  }
LABEL_304:
                  *(_DWORD *)v532 = 1;
                  LODWORD(m) = -1030155360;
                  continue;
                }
                if ( (_DWORD)m != -46331658 )
                {
                  if ( (_DWORD)m == (_DWORD)&loc_717BD84 )
                  {
                    v594 = (__int64)&v274;
                    v470 = &v274 - 2;
                    v532 = v312;
                    LODWORD(v313) = *v312;
                    LODWORD(m) = -1317797554;
                  }
                  continue;
                }
                v592[0] = nptr;
                v609 = (void *)v594;
                v349 = (unsigned __int64)v336;
                LOBYTE(v331) = *v336;
                v45 = 626639548;
                while ( 1 )
                {
                  while ( v45 <= 1678190980 )
                  {
                    if ( v45 > 626639547 )
                    {
                      if ( v45 == 626639548 )
                      {
                        v45 = 1678190981;
                        if ( ((unsigned __int8)v331 & 1) == 0 )
                          v45 = 1914451914;
                      }
                      else
                      {
                        LODWORD(v362) = v535;
                        v612 = (unsigned __int64)(v39 + 162);
                        v379 = (__int64)&v39[v535 + 162];
                        v45 = -2137033712;
                      }
                    }
                    else if ( v45 == -2137033712 )
                    {
                      *(_BYTE *)(v612 + v535++) = ((_BYTE)v362 + 1) ^ v39[161] ^ *(_BYTE *)v379 ^ 0xE;
                      v45 = -125087914;
                    }
                    else
                    {
LABEL_320:
                      v45 = 1806090338;
                    }
                  }
                  if ( v45 > 1914451913 )
                  {
                    if ( v45 != 1986973541 )
                    {
                      v616 = v39 + 162;
                      v396 = v470;
                      LODWORD(m) = 285114298;
                      goto LABEL_268;
                    }
                    v39[176] = 0;
                    v39[177] = 0;
                    *(_BYTE *)v349 = 0;
                    v45 = 1914451914;
                  }
                  else
                  {
                    if ( v45 == 1678190981 )
                    {
                      v354 = (unsigned __int64)&v535;
                      v535 = 0;
                      goto LABEL_320;
                    }
                    v45 = 1986973541;
                    if ( v535 < 0xE )
                      v45 = 1088045697;
                  }
                }
              }
              if ( (int)m > -1030155361 )
                break;
              if ( (_DWORD)m == -1567453562 )
                goto LABEL_304;
              if ( (_DWORD)m == -1317797554 )
              {
                LODWORD(m) = -882590125;
                if ( (_DWORD)v313 == 2 )
                  LODWORD(m) = -46331658;
              }
            }
            if ( (_DWORD)m != -1030155360 )
              break;
            if ( *(_OWORD **)&nptr[0] != &nptr[1] )
              operator delete(*(void **)&nptr[0]);
          }
          if ( (_DWORD)m == -998981451 )
          {
            sub_56957EC(v594, v616, v470);
            v41 = v594;
            v42 = -2054991384;
            while ( 1 )
            {
              while ( v42 > 239233623 )
              {
                if ( v42 > 910125071 )
                {
                  if ( v42 == 910125072 )
                  {
                    if ( *(_QWORD *)v594 != v594 + 16 )
                      operator delete(*(void **)v594);
                    LODWORD(m) = 1516859029;
                    if ( !*((_QWORD *)&nptr[0] + 1) )
                      LODWORD(m) = -1567453562;
                    goto LABEL_268;
                  }
                  *(_QWORD *)&nptr[0] = &nptr[1];
                  v44 = sub_56F9F18(&buf);
                  std::string::_M_construct<char const*>(nptr, &buf, &buf + v44);
                  v42 = 239233624;
                }
                else if ( v42 == 239233624 )
                {
                  v42 = 910125072;
                }
                else
                {
                  v43 = *(_QWORD *)(v41 + 8) == 0;
                  v42 = -1522720795;
LABEL_291:
                  if ( v43 )
                    v42 = -410617380;
                }
              }
              if ( v42 == -2054991384 )
              {
                v43 = qword_7DD5D40 == 0;
                v42 = 561185640;
                goto LABEL_291;
              }
              if ( v42 == -1522720795 )
              {
                if ( !qword_7DD5D40 )
                  std::__throw_bad_function_call();
                algn_7DD5D48(nptr, &unk_7DD5D30, v41);
                v42 = 910125072;
              }
              else
              {
                v379 = (__int64)&v612;
                v42 = 2006923965;
              }
            }
          }
          v3 = (char *)&v545 + 2;
          if ( (_DWORD)m != -882590125 )
            goto LABEL_268;
          i = 1454417878;
          if ( *(_DWORD *)v532 == 1 )
            i = 1837498014;
        }
        else if ( i == 1837498014 )
        {
          v3 = (char *)&v545 + 2;
          v366 = time(0);
          v345 = (unsigned __int64)v309;
          i = 1590858540;
          if ( !v309[1] )
            i = -1358538699;
        }
        else if ( i == 2063658932 )
        {
          v609 = v330;
          LOBYTE(v470) = *v330;
          v19 = 871992463;
          while ( 1 )
          {
            while ( v19 == -1686978069 )
            {
              *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
              *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
              *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
              *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
              v450 = (void *)0x29273D3D19792405LL;
              v451 = 0x77753F30342B3D7FLL;
              qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
              v453 = (void *)0x5D515D5D1A585223LL;
              v454 = 69;
              v455 = 91;
              v456 = 91;
              v457 = 18;
              qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
              v459 = 14;
              v460 = 71;
              v379 = (__int64)v463;
              v20 = 434048087;
              v21 = &v461;
              while ( v20 != -1401140967 )
              {
                *v21++ = 0;
                v20 = 434048087;
                if ( v21 == (char *)v379 )
                  v20 = -1401140967;
              }
              v354 = (unsigned __int64)nptr;
              LOBYTE(v396) = nptr[0];
              for ( n = -675995946; ; n = 740258254 )
              {
                while ( 1 )
                {
                  while ( n > 673470317 )
                  {
                    if ( n > 810545848 )
                    {
                      if ( n == 810545849 )
                      {
                        ++v349;
                      }
                      else
                      {
                        v612 = (unsigned __int64)&v349;
                        v349 = 0;
                      }
                      n = -495751738;
                    }
                    else if ( n == 673470318 )
                    {
                      v461 = 0;
                      v462 = 0;
                      *(_BYTE *)v354 = 0;
                      n = -958661634;
                    }
                    else
                    {
                      *(_BYTE *)v379 = v535;
                      n = 810545849;
                    }
                  }
                  if ( n <= -675995947 )
                    break;
                  if ( n == -675995946 )
                  {
                    n = 1310473308;
                    if ( ((unsigned __int8)v396 & 1) == 0 )
                      n = -958661634;
                  }
                  else
                  {
                    n = 673470318;
                    if ( v349 < 0x58 )
                      n = -2012962271;
                  }
                }
                if ( n != -2012962271 )
                  break;
                LOBYTE(v535) = BYTE1(nptr[0]) ^ *((_BYTE *)nptr + v349 + 2) ^ (v349 + 1) ^ 0x58;
                v379 = (__int64)nptr + v349 + 2;
              }
              v379 = 0x1C4B4C584C482F01LL;
              v380 = 94;
              v381 = 64;
              v382 = 86;
              v383 = 81;
              v384 = 69;
              v385 = 83;
              v386 = 23;
              qmemcpy(v387, "ZP]\vP^gK", sizeof(v387));
              v612 = (unsigned __int64)v390;
              v23 = -1483581872;
              v24 = &v388;
              while ( v23 != 949538836 )
              {
                *v24++ = 0;
                v23 = -1483581872;
                if ( v24 == (char *)v612 )
                  v23 = 949538836;
              }
              v396 = &v379;
              LOBYTE(v532) = v379;
              for ( ii = -589859761; ; ii = 566893418 )
              {
                while ( 1 )
                {
                  while ( ii <= 329061499 )
                  {
                    if ( ii > -1114745981 )
                    {
                      if ( ii == -1114745980 )
                      {
                        v535 = (unsigned __int64)&v616;
                        v616 = 0;
                        ii = 566893418;
                      }
                      else
                      {
                        ii = -1114745980;
                        if ( ((unsigned __int8)v532 & 1) == 0 )
                          ii = 550623121;
                      }
                    }
                    else if ( ii == -1815071978 )
                    {
                      v354 = (unsigned __int64)&v379 + 2;
                      LOBYTE(v592[0]) = BYTE1(v379) ^ *((_BYTE *)v616 + (_QWORD)&v379 + 2) ^ (v349 + 1) ^ 0x15;
                      v612 = (unsigned __int64)v616;
                      ii = 329061500;
                    }
                    else
                    {
                      v388 = 0;
                      v389 = 0;
                      *v396 = 0;
                      ii = 550623121;
                    }
                  }
                  if ( ii <= 566893417 )
                    break;
                  if ( ii == 566893418 )
                  {
                    ii = -1389502703;
                    if ( (unsigned __int64)v616 < 0x15 )
                      ii = 1904956769;
                  }
                  else
                  {
                    v349 = (unsigned __int64)v616;
                    ii = -1815071978;
                  }
                }
                if ( ii != 329061500 )
                  break;
                *(_BYTE *)(v354 + v612) = v592[0];
                v616 = (char *)v616 + 1;
              }
              sub_56A4A43((char *)nptr + 2, 71, (char *)&v379 + 2, "[FGESDK]", 1);
              *(_BYTE *)v609 = 1;
              v26 = v344;
              v379 = (__int64)v344;
              sub_576FA2C(nptr, 1, &v379);
              v27 = nptr[0];
              nptr[0] = 0;
              *((_QWORD *)v26 + 45) = v27;
              v28 = *((_QWORD *)v26 + 46);
              *((_QWORD *)v26 + 46) = *((_QWORD *)&v27 + 1);
              if ( v28 )
              {
                sub_56E4FDE();
                if ( *((_QWORD *)&nptr[0] + 1) )
                  sub_56E4FDE();
              }
              v19 = -1197020138;
              v3 = (char *)&v545 + 2;
            }
            if ( v19 == -1197020138 )
              break;
            v19 = -1197020138;
            if ( ((unsigned __int8)v470 & 1) == 0 )
              v19 = -1686978069;
          }
          i = -961197315;
        }
        else
        {
          v609 = v330;
          LOBYTE(v470) = *v330;
          v7 = 871992463;
          while ( 1 )
          {
            while ( v7 == -1686978069 )
            {
              *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
              *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
              *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
              *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
              v450 = (void *)0x29273D3D19792405LL;
              v451 = 0x77753F30342B3D7FLL;
              qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
              v453 = (void *)0x5D515D5D1A585223LL;
              v454 = 69;
              v455 = 91;
              v456 = 91;
              v457 = 18;
              qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
              v459 = 14;
              v460 = 71;
              v379 = (__int64)v463;
              v8 = 434048087;
              v9 = &v461;
              while ( v8 != -1401140967 )
              {
                *v9++ = 0;
                v8 = 434048087;
                if ( v9 == (char *)v379 )
                  v8 = -1401140967;
              }
              v354 = (unsigned __int64)nptr;
              LOBYTE(v396) = nptr[0];
              for ( jj = -675995946; ; jj = 740258254 )
              {
                while ( 1 )
                {
                  while ( jj > 673470317 )
                  {
                    if ( jj > 810545848 )
                    {
                      if ( jj == 810545849 )
                      {
                        ++v349;
                      }
                      else
                      {
                        v612 = (unsigned __int64)&v349;
                        v349 = 0;
                      }
                      jj = -495751738;
                    }
                    else if ( jj == 673470318 )
                    {
                      v461 = 0;
                      v462 = 0;
                      *(_BYTE *)v354 = 0;
                      jj = -958661634;
                    }
                    else
                    {
                      *(_BYTE *)v379 = v535;
                      jj = 810545849;
                    }
                  }
                  if ( jj <= -675995947 )
                    break;
                  if ( jj == -675995946 )
                  {
                    jj = 1310473308;
                    if ( ((unsigned __int8)v396 & 1) == 0 )
                      jj = -958661634;
                  }
                  else
                  {
                    jj = 673470318;
                    if ( v349 < 0x58 )
                      jj = -2012962271;
                  }
                }
                if ( jj != -2012962271 )
                  break;
                LOBYTE(v535) = BYTE1(nptr[0]) ^ *((_BYTE *)nptr + v349 + 2) ^ (v349 + 1) ^ 0x58;
                v379 = (__int64)nptr + v349 + 2;
              }
              v379 = 0x1C4B4C584C482F01LL;
              v380 = 94;
              v381 = 64;
              v382 = 86;
              v383 = 81;
              v384 = 69;
              v385 = 83;
              v386 = 23;
              qmemcpy(v387, "ZP]\vP^gK", sizeof(v387));
              v612 = (unsigned __int64)v390;
              v11 = -1483581872;
              v12 = &v388;
              while ( v11 != 949538836 )
              {
                *v12++ = 0;
                v11 = -1483581872;
                if ( v12 == (char *)v612 )
                  v11 = 949538836;
              }
              v396 = &v379;
              LOBYTE(v532) = v379;
              for ( kk = -589859761; ; kk = 566893418 )
              {
                while ( 1 )
                {
                  while ( kk <= 329061499 )
                  {
                    if ( kk > -1114745981 )
                    {
                      if ( kk == -1114745980 )
                      {
                        v535 = (unsigned __int64)&v616;
                        v616 = 0;
                        kk = 566893418;
                      }
                      else
                      {
                        kk = -1114745980;
                        if ( ((unsigned __int8)v532 & 1) == 0 )
                          kk = 550623121;
                      }
                    }
                    else if ( kk == -1815071978 )
                    {
                      v354 = (unsigned __int64)&v379 + 2;
                      LOBYTE(v592[0]) = BYTE1(v379) ^ *((_BYTE *)v616 + (_QWORD)&v379 + 2) ^ (v349 + 1) ^ 0x15;
                      v612 = (unsigned __int64)v616;
                      kk = 329061500;
                    }
                    else
                    {
                      v388 = 0;
                      v389 = 0;
                      *v396 = 0;
                      kk = 550623121;
                    }
                  }
                  if ( kk <= 566893417 )
                    break;
                  if ( kk == 566893418 )
                  {
                    kk = -1389502703;
                    if ( (unsigned __int64)v616 < 0x15 )
                      kk = 1904956769;
                  }
                  else
                  {
                    v349 = (unsigned __int64)v616;
                    kk = -1815071978;
                  }
                }
                if ( kk != 329061500 )
                  break;
                *(_BYTE *)(v354 + v612) = v592[0];
                v616 = (char *)v616 + 1;
              }
              sub_56A4A43((char *)nptr + 2, 71, (char *)&v379 + 2, "[FGESDK]", 1);
              *(_BYTE *)v609 = 1;
              v14 = v344;
              v379 = (__int64)v344;
              sub_576FA2C(nptr, 1, &v379);
              v15 = nptr[0];
              nptr[0] = 0;
              *((_QWORD *)v14 + 45) = v15;
              v16 = *((_QWORD *)v14 + 46);
              *((_QWORD *)v14 + 46) = *((_QWORD *)&v15 + 1);
              if ( v16 )
              {
                sub_56E4FDE();
                if ( *((_QWORD *)&nptr[0] + 1) )
                  sub_56E4FDE();
              }
              v7 = -1197020138;
              v3 = (char *)&v545 + 2;
            }
            if ( v7 == -1197020138 )
              break;
            v7 = -1197020138;
            if ( ((unsigned __int8)v470 & 1) == 0 )
              v7 = -1686978069;
          }
LABEL_96:
          i = 336292162;
        }
      }
      if ( i > 1349638111 )
        break;
      if ( i == 438638509 )
      {
        v338 = &v274 - 4;
        p_mutex = &mutex;
        i = 1538019841;
      }
      else
      {
        i = -961197315;
        if ( (signed __int64)v367 > *((_QWORD *)v344 + 32) )
          i = 2063658932;
      }
    }
    if ( i != 1454417878 )
      break;
    v340 = &v545;
  }
  if ( i == 1515531231 )
  {
    v399 = (__int64)&v485;
    i = -917410991;
    goto LABEL_2;
  }
  sub_56E5DF8(mutex);
  v283 = (_BYTE *)sub_56CE9EA();
  v294 = &v469;
  v295 = &v467;
  v307 = v344 + 264;
  v308 = (__int64)(v344 + 266);
  v336 = v344 + 64;
  v312 = v344 + 16;
  v309 = v344 + 104;
  v310 = (pthread_mutex_t *)(v344 + 384);
  i3 = (__int64)(v344 + 232);
  v284 = (__int64 *)(v344 + 232);
  v296 = v344 + 376;
  v48 = 1153267325;
LABEL_345:
  v49 = 1831282351;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( v48 <= 575704835 )
            {
              if ( v48 <= -1176336300 )
              {
                if ( v48 > -1657238167 )
                {
                  if ( v48 > -1266731696 )
                  {
                    if ( v48 == -1266731695 )
                    {
                      v275 = *v276;
                      v48 = -1441965674;
                    }
                    else
                    {
                      v337 = (unsigned int)sub_56F4EF0(v373, v274, v46, i3, 2282005025LL, v592, v620[0]) == 0;
                      v48 = 1409059716;
                    }
                  }
                  else if ( v48 == -1657238166 )
                  {
                    v288 = &v396[-v280];
                    v48 = -250399397;
                    if ( (__int64)&v396[-v280] <= 0 )
                      v48 = 2129687011;
                  }
                  else
                  {
                    v48 = -2007905915;
                    if ( (__int64)v288 < v275 )
                      v48 = -1780504402;
                  }
                }
                else if ( v48 > -1892412571 )
                {
                  v274 = v336;
                  v48 = -1201808032;
                }
                else
                {
                  if ( v48 != -2028960908 )
                  {
                    std::string::_M_assign(&v370, v397);
                    goto LABEL_411;
                  }
                  v396 = (_BYTE *)v347[8];
                  v397[0] = v398;
                  std::string::_M_construct<char *>(v397, v347[9], v347[9] + v347[10]);
                  v48 = -1657238166;
                }
              }
              else if ( v48 <= -306376797 )
              {
                if ( v48 > -562262635 )
                {
                  if ( v48 == -562262634 )
                  {
LABEL_411:
                    v48 = 1634052705;
                  }
                  else
                  {
                    v48 = 2106276885;
                    if ( !(unsigned int)sub_56F4EF0(v373, v336, v46, i3, 2282005025LL, v592, v620[0]) )
                      v48 = 616125115;
                  }
                }
                else if ( v48 == -1176336299 )
                {
                  v291 = &v347;
                  v290 = v312;
                  v279 = sub_57041F8(v312, v373, v46, i3, 2282005025LL, v592);
                  v278 = (__int64 *)&v347;
                  v48 = 575704836;
                }
                else
                {
                  v48 = 911994299;
                }
              }
              else if ( v48 <= 5790774 )
              {
                if ( v48 == -306376796 )
                {
                  v354 = (unsigned __int64)&v375;
                  LOBYTE(v616) = v375;
                  for ( mm = -196428389; ; mm = -2143072540 )
                  {
                    while ( 1 )
                    {
                      while ( mm <= -196428390 )
                      {
                        if ( mm > -1411366535 )
                        {
                          if ( mm == -1411366534 )
                          {
                            *(_BYTE *)(v485 + v349) = (v535 + 1) ^ BYTE1(v375) ^ *((_BYTE *)v545 + v485) ^ 0xF;
                            *(_QWORD *)&nptr[0] = v349 + 1;
                            mm = -526337747;
                          }
                          else
                          {
                            v349 = *(_QWORD *)&nptr[0];
                            mm = -2143072540;
                          }
                        }
                        else if ( mm == -2143072540 )
                        {
                          mm = -1868472629;
                          if ( v349 < 0xF )
                            mm = 743577125;
                        }
                        else
                        {
                          v377[0] = 0;
                          v377[1] = 0;
                          *(_BYTE *)v354 = 0;
                          mm = 2090892035;
                        }
                      }
                      if ( mm > 2090892034 )
                        break;
                      if ( mm == -196428389 )
                      {
                        mm = 2124246479;
                        if ( ((unsigned __int8)v616 & 1) == 0 )
                          mm = 2090892035;
                      }
                      else
                      {
                        LODWORD(v535) = v349;
                        v485 = (unsigned __int64)&v375 + 2;
                        v545 = (void *)v349;
                        mm = -1411366534;
                      }
                    }
                    if ( mm != 2124246479 )
                      break;
                    v612 = (unsigned __int64)&v349;
                    v349 = 0;
                  }
                  sub_56A4A43(v277, 120, (char *)&v375 + 2, "[FGESDK]", 1);
                  v48 = 1385966020;
                  if ( !(unsigned int)sub_56F4EF0(v373, v336, v54, v55, v56, v57, v620[0]) )
                    v48 = 1381601663;
                }
                else
                {
                  v276 = v284;
                  v48 = -1266731695;
                }
              }
              else if ( v48 == 5790775 )
              {
                v289 = &v396;
                v48 = -2028960908;
              }
              else if ( v48 == 230961172 )
              {
                v485 = (unsigned __int64)&v379;
                LOBYTE(v349) = v379;
                for ( nn = -675995946; ; nn = 740258254 )
                {
                  while ( 1 )
                  {
                    while ( nn > 673470317 )
                    {
                      if ( nn > 810545848 )
                      {
                        if ( nn == 810545849 )
                        {
                          ++v612;
                        }
                        else
                        {
                          v545 = &v612;
                          v612 = 0;
                        }
                        nn = -495751738;
                      }
                      else if ( nn == 673470318 )
                      {
                        v394[0] = 0;
                        v394[1] = 0;
                        *(_BYTE *)v485 = 0;
                        nn = -958661634;
                      }
                      else
                      {
                        **(_BYTE **)&nptr[0] = v354;
                        nn = 810545849;
                      }
                    }
                    if ( nn <= -675995947 )
                      break;
                    if ( nn == -675995946 )
                    {
                      nn = 1310473308;
                      if ( (v349 & 1) == 0 )
                        nn = -958661634;
                    }
                    else
                    {
                      nn = 673470318;
                      if ( v612 < 0x58 )
                        nn = -2012962271;
                    }
                  }
                  if ( nn != -2012962271 )
                    break;
                  LOBYTE(v354) = BYTE1(v379) ^ *((_BYTE *)&v379 + v612 + 2) ^ (v612 + 1) ^ 0x58;
                  *(_QWORD *)&nptr[0] = (char *)&v379 + v612 + 2;
                }
                v277 = (char *)&v379 + 2;
                v286 = &v375;
                v375 = 0x4D4A705747462F01LL;
                qmemcpy(v376, "BF\tOS\\D\\J", sizeof(v376));
                *(_QWORD *)&nptr[0] = &v378;
                i3 = 489240818;
                v59 = v377;
                while ( (_DWORD)i3 != 1338555522 )
                {
                  *v59++ = 0;
                  i3 = 489240818;
                  v46 = 1338555522;
                  if ( v59 == *(_BYTE **)&nptr[0] )
                    i3 = 1338555522;
                }
                v48 = -306376796;
              }
              else
              {
                v280 = time(0);
                v48 = -1176336299;
              }
            }
            if ( v48 > 1409059715 )
              break;
            if ( v48 <= 946759077 )
            {
              if ( v48 > 616125114 )
              {
                if ( v48 == 616125115 )
                {
                  v311 = v620;
                  v137 = -1257953567;
                  v3 = v344;
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
                          while ( v137 <= -297893535 )
                          {
                            if ( v137 > -839058133 )
                            {
                              if ( v137 <= -478004355 )
                              {
                                if ( v137 != -839058132 )
                                {
                                  sub_56E5DF8(v348);
                                  v48 = 2106276885;
                                  goto LABEL_345;
                                }
                                v137 = 1095165697;
                              }
                              else if ( v137 == -478004354 )
                              {
                                v343 = v305 < 4;
                                v137 = 2031218905;
                              }
                              else
                              {
                                v137 = 1095165697;
                                i3 = 4190006973LL;
                                if ( (v3[96] & 1) == 0 )
                                  v137 = -104960323;
                              }
                            }
                            else if ( v137 > -1672859853 )
                            {
                              if ( v137 == -1672859852 )
                              {
                                v192 = v334;
                                *v334 = 1;
                                v192[1] = 47;
                                v192[2] = 85;
                                v192[3] = 74;
                                v192[4] = 76;
                                v192[5] = 5;
                                v192[6] = 65;
                                v192[7] = 74;
                                v192[8] = 86;
                                v192[9] = 93;
                                v192[10] = 81;
                                v192[11] = 10;
                                v192[12] = 2;
                                v192[13] = 8;
                                v192[14] = 95;
                                v192[15] = 6;
                                v193 = v192 + 16;
                                *(_QWORD *)&nptr[0] = v192 + 18;
                                v194 = 1244424498;
                                while ( v194 != -1410437110 )
                                {
                                  *v193++ = 0;
                                  v194 = 1244424498;
                                  if ( v193 == *(_BYTE **)&nptr[0] )
                                    v194 = -1410437110;
                                }
                                v195 = v334;
                                v612 = (unsigned __int64)v334;
                                LOBYTE(v535) = *v334;
                                v196 = v334 + 2;
                                for ( i1 = 626639548; ; i1 = 1914451914 )
                                {
                                  while ( 1 )
                                  {
                                    while ( i1 <= 1678190980 )
                                    {
                                      if ( i1 > 626639547 )
                                      {
                                        if ( i1 == 626639548 )
                                        {
                                          i1 = 1678190981;
                                          if ( (v535 & 1) == 0 )
                                            i1 = 1914451914;
                                        }
                                        else
                                        {
                                          LODWORD(v349) = v354;
                                          v545 = v196;
                                          *(_QWORD *)&nptr[0] = &v196[v354];
                                          i1 = -2137033712;
                                        }
                                      }
                                      else if ( i1 == -2137033712 )
                                      {
                                        *((_BYTE *)v545 + v354++) = (v349 + 1) ^ v195[1] ^ **(_BYTE **)&nptr[0] ^ 0xE;
                                        i1 = -125087914;
                                      }
                                      else
                                      {
LABEL_1594:
                                        i1 = 1806090338;
                                      }
                                    }
                                    if ( i1 > 1914451913 )
                                      break;
                                    if ( i1 == 1678190981 )
                                    {
                                      v485 = (unsigned __int64)&v354;
                                      v354 = 0;
                                      goto LABEL_1594;
                                    }
                                    i1 = 1986973541;
                                    if ( v354 < 0xE )
                                      i1 = 1088045697;
                                  }
                                  if ( i1 != 1986973541 )
                                    break;
                                  v195[16] = 0;
                                  v195[17] = 0;
                                  *(_BYTE *)v612 = 0;
                                }
                                sub_56A4A43(v304, 148, v196, "[FGESDK]", 2);
                                v137 = -575301484;
                                v3 = v344;
                              }
                              else
                              {
                                v335 = v620;
                                v334 = &v617;
                                v329 = &v348;
                                v306 = v310;
                                v137 = 1928266301;
                              }
                            }
                            else if ( v137 == -1977634016 )
                            {
                              v305 = *((_QWORD *)v333 + 1);
                              v137 = -478004354;
                            }
                            else
                            {
                              v328 = v335;
                              v137 = -297893534;
                            }
                          }
                          if ( v137 <= 1095165696 )
                            break;
                          if ( v137 > 1928266300 )
                          {
                            if ( v137 == 1928266301 )
                            {
                              v348 = v306;
                              sub_56E5AFC(v306);
                              v3 = v344;
                              v333 = v336;
                              v137 = -1977634016;
                              i3 = 2605311197LL;
                              if ( !*((_QWORD *)v336 + 1) )
                                v137 = -1689656099;
                            }
                            else
                            {
                              v137 = -413123324;
                              i3 = 2605311197LL;
                              if ( v343 )
                                v137 = -1689656099;
                            }
                          }
                          else if ( v137 == 1095165697 )
                          {
                            v137 = -575301484;
                          }
                          else
                          {
                            v138 = v303;
                            v545 = v309;
                            v46 = v303 - *v309;
                            *(_QWORD *)&nptr[0] = v46;
                            v139 = *((_QWORD *)v3 + 30);
                            for ( i2 = 563187957; ; i2 = -1643462965 )
                            {
                              while ( i2 > 134251944 )
                              {
                                if ( i2 == 134251945 )
                                {
                                  i2 = -1991102596;
                                  if ( (_BYTE)v485 )
                                    i2 = 1392767983;
                                }
                                else if ( i2 == 1392767983 )
                                {
                                  i2 = -1643462965;
                                  v46 = 0;
                                }
                                else
                                {
                                  LOBYTE(v485) = *(_QWORD *)&nptr[0] < v139;
                                  i2 = 134251945;
                                }
                              }
                              if ( i2 != -1991102596 )
                                break;
                              v46 = (__int64)v545;
                              *(_QWORD *)v545 = v138;
                              LOBYTE(v46) = 1;
                            }
                            v137 = -839058132;
                            i3 = 4271504012LL;
                            if ( (v46 & 1) != 0 )
                              v137 = -23463284;
                          }
                        }
                        if ( v137 != -297893534 )
                          break;
                        v198 = v335;
                        *v335 = 1;
                        v198[1] = 47;
                        v198[2] = 89;
                        v198[3] = 7;
                        v198[4] = 27;
                        v198[5] = 28;
                        v198[6] = 6;
                        v198[7] = 94;
                        v198[8] = 20;
                        v198[9] = 26;
                        v198[10] = 8;
                        v198[11] = 18;
                        v198[12] = 12;
                        v198[13] = 8;
                        v198[14] = 85;
                        v198[15] = 21;
                        v198[16] = 17;
                        v198[17] = 9;
                        v198[18] = 19;
                        v198[19] = 29;
                        LOBYTE(v49) = 75;
                        v198[20] = 75;
                        v198[21] = 27;
                        v198[22] = 84;
                        v198[23] = 85;
                        v198[24] = 79;
                        v198[25] = 31;
                        v198[26] = 2;
                        v198[27] = 12;
                        v198[28] = 24;
                        v198[29] = 13;
                        v198[30] = 5;
                        v198[31] = 27;
                        v198[32] = 5;
                        v198[33] = 36;
                        v198[34] = 121;
                        v198[35] = 25;
                        v198[36] = 61;
                        v198[37] = 61;
                        v198[38] = 39;
                        v198[39] = 41;
                        v198[40] = 127;
                        qmemcpy(v198 + 41, "=+40?uwvhhkkmln$*8$/.>&#RX", 26);
                        v198[67] = 26;
                        v198[68] = 93;
                        v198[69] = 93;
                        v198[70] = 81;
                        v198[71] = 93;
                        v198[72] = 69;
                        v198[73] = 91;
                        v198[74] = 91;
                        v198[75] = 18;
                        qmemcpy(v198 + 76, "X^LP[ByQKHGO", 12);
                        LOBYTE(v46) = 79;
                        v198[88] = 14;
                        v198[89] = 71;
                        v199 = v198 + 90;
                        *(_QWORD *)&nptr[0] = v198 + 92;
                        v200 = 434048087;
                        while ( v200 != -1401140967 )
                        {
                          *v199++ = 0;
                          v200 = 434048087;
                          v46 = 2893826329LL;
                          if ( v199 == *(_BYTE **)&nptr[0] )
                            v200 = -1401140967;
                        }
                        v201 = v335;
                        v485 = (unsigned __int64)v335;
                        LOBYTE(v349) = *v335;
                        for ( i3 = 3618971350LL; ; i3 = 740258254 )
                        {
                          while ( 1 )
                          {
                            while ( (int)i3 > 673470317 )
                            {
                              if ( (int)i3 > 810545848 )
                              {
                                if ( (_DWORD)i3 == 810545849 )
                                {
                                  ++v612;
                                }
                                else
                                {
                                  v545 = &v612;
                                  v612 = 0;
                                }
                                i3 = 3799215558LL;
                              }
                              else if ( (_DWORD)i3 == 673470318 )
                              {
                                v46 = 0;
                                v201[90] = 0;
                                v201[91] = 0;
                                *(_BYTE *)v485 = 0;
                                i3 = 3336305662LL;
                              }
                              else
                              {
                                v46 = *(_QWORD *)&nptr[0];
                                **(_BYTE **)&nptr[0] = v354;
                                i3 = 810545849;
                              }
                            }
                            if ( (int)i3 <= -675995947 )
                              break;
                            if ( (_DWORD)i3 == -675995946 )
                            {
                              i3 = 1310473308;
                              if ( (v349 & 1) == 0 )
                                i3 = 3336305662LL;
                            }
                            else
                            {
                              i3 = 673470318;
                              if ( v612 < 0x58 )
                                i3 = 2282005025LL;
                            }
                          }
                          if ( (_DWORD)i3 != -2012962271 )
                            break;
                          v46 = v612;
                          LOBYTE(v354) = v201[1] ^ v201[v612 + 2] ^ (v612 + 1) ^ 0x58;
                          *(_QWORD *)&nptr[0] = &v201[v612 + 2];
                        }
                        v304 = v201 + 2;
                        v327 = v334;
                        v137 = -1672859852;
                      }
                      if ( v137 != -104960323 )
                        break;
                      v202 = time(0);
                      v3 = v344;
                      v303 = v202;
                      v137 = 1769080040;
                    }
                    v315 = v620;
                    v326 = v3;
                    v141 = -1247314067;
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
LABEL_1130:
                          while ( v141 > -230113715 )
                          {
                            if ( v141 <= 1352552604 )
                            {
                              if ( v141 == -230113714 )
                              {
                                std::_Rb_tree<int const,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int const>,std::allocator<std::pair<int const,std::string>>>::_M_erase(
                                  &v354,
                                  v356,
                                  v46,
                                  i3,
                                  2282005025LL,
                                  v592);
                              }
                              else
                              {
                                if ( v141 != 680291346 )
                                {
                                  LOBYTE(v142) = (_BYTE)v344;
                                  v143 = (char *)&v545 + 2;
                                  v322 = &v532;
                                  sub_570482E(&v349, &v354, v46, i3, 2282005025LL, v592);
                                  v314 = v620;
                                  v148 = 985969181;
                                  while ( 1 )
                                  {
                                    while ( 1 )
                                    {
                                      while ( v148 > -657443510 )
                                      {
                                        if ( v148 <= 983097492 )
                                        {
                                          if ( v148 == -657443509 )
                                          {
                                            v148 = -2111804588;
                                            v145 = 1206600332;
                                            if ( (char *)v361 == &v350 )
                                              v148 = 1206600332;
                                          }
                                          else if ( v148 == 924154336 )
                                          {
                                            v360 = sub_57041F8(v316, v336, v144, v145, v146, v147);
                                            v145 = (__int64)(v316 + 2);
                                            v342 = v360 != (_QWORD)(v316 + 2);
                                            v148 = -1990518946;
                                          }
                                          else
                                          {
                                            v609 = &v611;
                                            std::string::_M_construct<char *>(
                                              &v609,
                                              *(_QWORD *)(v313 + 8),
                                              *(_QWORD *)(v313 + 8) + *(_QWORD *)(v313 + 16));
                                            v49 = (unsigned __int64)&off_7CA2800;
                                            v613.m256i_i32[0] = v332;
                                            v613.m256i_i64[1] = (__int64)&v613.m256i_i64[3];
                                            std::string::_M_construct<char *>(
                                              &v613.m256i_u64[1],
                                              v609,
                                              (char *)v609 + v610);
                                            sub_5704264(v298, &v612);
                                            v612 = (unsigned __int64)&off_7CA2800;
                                            if ( (unsigned __int64 *)v613.m256i_i64[1] != &v613.m256i_u64[3] )
                                              operator delete((void *)v613.m256i_i64[1]);
                                            if ( v609 != &v611 )
                                              operator delete(v609);
                                            v361 = std::_Rb_tree_increment(v361);
                                            v148 = -1386401952;
                                          }
                                        }
                                        else if ( v148 <= 1188221911 )
                                        {
                                          if ( v148 != 985969181 )
                                          {
                                            std::_Rb_tree<int const,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int const>,std::allocator<std::pair<int const,std::string>>>::_M_erase(
                                              &v349,
                                              v351,
                                              v144,
                                              v145,
                                              v146,
                                              v147);
                                            v321 = &v485;
                                            v485 = 0x5E061C1B07592F01LL;
                                            v486 = 20;
                                            v487 = 26;
                                            v488 = 8;
                                            v489 = 18;
                                            v490 = 12;
                                            v491 = 8;
                                            v492 = 85;
                                            v493 = 21;
                                            v494 = 17;
                                            v495 = 9;
                                            v496 = 19;
                                            v497 = 29;
                                            v498 = 75;
                                            v499 = 27;
                                            v500 = 84;
                                            v501 = 85;
                                            v502 = 79;
                                            v503 = 31;
                                            v504 = 2;
                                            v505 = 12;
                                            v506 = 24;
                                            v507 = 13;
                                            v508 = 5;
                                            v509 = 27;
                                            v510 = 5;
                                            v511 = 36;
                                            v512 = 121;
                                            v513 = 25;
                                            qmemcpy(v514, "==')", sizeof(v514));
                                            v515 = 127;
                                            qmemcpy(v516, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v516));
                                            v517 = 26;
                                            v518 = 93;
                                            v519 = 93;
                                            v520 = 81;
                                            v521 = 93;
                                            v522 = 69;
                                            v523 = 91;
                                            v524 = 91;
                                            v525 = 18;
                                            qmemcpy(v526, "X^LP[ByQKHGO", sizeof(v526));
                                            v527 = 14;
                                            v528 = 71;
                                            *(_QWORD *)&nptr[0] = v531;
                                            v159 = 434048087;
                                            v160 = &v529;
                                            v3 = v344;
                                            v46 = (__int64)&v485 + 2;
                                            while ( v159 != -1401140967 )
                                            {
                                              *v160++ = 0;
                                              v159 = 434048087;
                                              if ( v160 == *(char **)&nptr[0] )
                                                v159 = -1401140967;
                                            }
                                            v616 = &v485;
                                            LOBYTE(v594) = v485;
                                            for ( i4 = -675995946; ; i4 = 740258254 )
                                            {
                                              while ( 1 )
                                              {
                                                while ( i4 > 673470317 )
                                                {
                                                  if ( i4 > 810545848 )
                                                  {
                                                    if ( i4 == 810545849 )
                                                    {
                                                      v609 = (char *)v609 + 1;
                                                    }
                                                    else
                                                    {
                                                      v612 = (unsigned __int64)&v609;
                                                      v609 = 0;
                                                    }
                                                    i4 = -495751738;
                                                  }
                                                  else if ( i4 == 673470318 )
                                                  {
                                                    v529 = 0;
                                                    v530 = 0;
                                                    *(_BYTE *)v616 = 0;
                                                    i4 = -958661634;
                                                  }
                                                  else
                                                  {
                                                    **(_BYTE **)&nptr[0] = v592[0];
                                                    i4 = 810545849;
                                                  }
                                                }
                                                if ( i4 <= -675995947 )
                                                  break;
                                                if ( i4 == -675995946 )
                                                {
                                                  i4 = 1310473308;
                                                  if ( (v594 & 1) == 0 )
                                                    i4 = -958661634;
                                                }
                                                else
                                                {
                                                  i4 = 673470318;
                                                  if ( (unsigned __int64)v609 < 0x58 )
                                                    i4 = -2012962271;
                                                }
                                              }
                                              if ( i4 != -2012962271 )
                                                break;
                                              LOBYTE(v592[0]) = BYTE1(v485)
                                                              ^ *((_BYTE *)v609 + (_QWORD)&v485 + 2)
                                                              ^ ((_BYTE)v609 + 1)
                                                              ^ 0x58;
                                              *(_QWORD *)&nptr[0] = (char *)v609 + (_QWORD)&v485 + 2;
                                            }
                                            v300 = (char *)&v485 + 2;
                                            v320 = &v473;
                                            v473 = 0x5C1D57585B492F01LL;
                                            LOBYTE(v46) = 91;
                                            v474 = 74;
                                            v475 = 86;
                                            v476 = 87;
                                            v477 = 18;
                                            qmemcpy(v478, "AQFC[\\\tFNB", sizeof(v478));
                                            v479 = 23;
                                            v480 = 11;
                                            v481 = 75;
                                            *(_QWORD *)&nptr[0] = v484;
                                            i3 = 3160756352LL;
                                            v168 = &v482;
                                            while ( (_DWORD)i3 != -919254716 )
                                            {
                                              *v168++ = 0;
                                              i3 = 3160756352LL;
                                              v46 = 3375712580LL;
                                              if ( v168 == *(char **)&nptr[0] )
                                                i3 = 3375712580LL;
                                            }
                                            v609 = &v473;
                                            LOBYTE(v345) = v473;
                                            for ( i5 = 185907318; ; i5 = 1982752890 )
                                            {
                                              while ( 1 )
                                              {
                                                while ( i5 > 886249242 )
                                                {
                                                  if ( i5 > 1108581097 )
                                                  {
                                                    if ( i5 == 1108581098 )
                                                    {
                                                      i5 = 886249243;
                                                      i3 = 174559871;
                                                      if ( v592[0] < (char *)&dword_14 + 3 )
                                                        i5 = 174559871;
                                                    }
                                                    else
                                                    {
                                                      i3 = v612;
                                                      LOBYTE(v46) = v367;
                                                      *((_BYTE *)v592[0]++ + v612) = v367;
                                                      i5 = 1108581098;
                                                    }
                                                  }
                                                  else if ( i5 == 886249243 )
                                                  {
                                                    i3 = 0;
                                                    v482 = 0;
                                                    v483 = 0;
                                                    *(_BYTE *)v609 = 0;
                                                    i5 = 862340680;
                                                  }
                                                  else
                                                  {
                                                    v616 = v592;
                                                    v592[0] = 0;
                                                    i5 = 1108581098;
                                                  }
                                                }
                                                if ( i5 > 366432057 )
                                                  break;
                                                if ( i5 == 174559871 )
                                                {
                                                  LODWORD(v594) = v592[0];
                                                  v612 = (unsigned __int64)&v473 + 2;
                                                  *(void **)&nptr[0] = v592[0];
                                                  i5 = 366432058;
                                                }
                                                else
                                                {
                                                  i5 = 920627274;
                                                  if ( (v345 & 1) == 0 )
                                                    i5 = 862340680;
                                                }
                                              }
                                              if ( i5 != 366432058 )
                                                break;
                                              i3 = (unsigned int)v594;
                                              LOBYTE(i3) = v594 + 1;
                                              LOBYTE(v367) = (v594 + 1)
                                                           ^ BYTE1(v473)
                                                           ^ *(_BYTE *)(v612 + *(_QWORD *)&nptr[0])
                                                           ^ 0x17;
                                            }
                                            v299 = (char *)&v473 + 2;
                                            v141 = -1936494864;
                                            goto LABEL_1130;
                                          }
                                          v148 = 1188221912;
                                          v145 = 2949622140LL;
                                          if ( !v353 )
                                            v148 = -1345345156;
                                        }
                                        else if ( v148 == 1188221912 )
                                        {
                                          v319 = &v361;
                                          v361 = v352;
                                          v318 = nptr;
                                          *(_QWORD *)&nptr[0] = &off_7CA2848;
                                          v145 = 0;
                                          memset((char *)nptr + 8, 0, 24);
                                          v450 = v452;
                                          v451 = 0;
                                          v452[0] = 0;
                                          v317 = &v360;
                                          v316 = v312;
                                          v148 = 924154336;
                                        }
                                        else
                                        {
                                          v330 = v620;
                                          for ( LODWORD(v149) = -1405111860; ; LODWORD(v149) = 139007939 )
                                          {
                                            while ( 1 )
                                            {
                                              while ( (int)v149 > 566702138 )
                                              {
                                                if ( (_DWORD)v149 == 566702139 )
                                                {
                                                  v345 = v451;
                                                  v150 = 15683199;
                                                  while ( v150 != -1747789055 )
                                                  {
                                                    if ( v150 == -905888113 )
                                                    {
                                                      for ( i6 = 693113538; ; i6 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( i6 > 693113537 )
                                                            {
                                                              if ( i6 > 1563511586 )
                                                              {
                                                                if ( i6 == 1563511587 )
                                                                {
                                                                  LOBYTE(v149) = v366 | 0x80;
                                                                  i6 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i6 = 1072704708;
                                                                  if ( !v367 )
                                                                    i6 = -1340685559;
                                                                }
                                                              }
                                                              else if ( i6 == 693113538 )
                                                              {
                                                                i6 = -1752948638;
                                                                v49 = 18;
                                                              }
                                                              else
                                                              {
                                                                v592[0] = *(void **)v594;
                                                                i6 = -1331101447;
                                                              }
                                                            }
                                                            if ( i6 <= -475423978 )
                                                              break;
                                                            if ( i6 == -475423977 )
                                                            {
                                                              v367 = (unsigned __int64)v616 >> 7;
                                                              v594 = (__int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v149);
                                                              i6 = 1696537547;
                                                              if ( v367 > 0x7F )
                                                                i6 = -1752948638;
                                                              v49 = v367;
                                                            }
                                                            else
                                                            {
                                                              i6 = -1340685559;
                                                            }
                                                          }
                                                          if ( i6 != -1752948638 )
                                                            break;
                                                          v616 = (void *)v49;
                                                          LOBYTE(v366) = v49;
                                                          i6 = -475423977;
                                                          if ( v49 >= 0x81 )
                                                            i6 = 1563511587;
                                                          LOBYTE(v149) = v366;
                                                        }
                                                        if ( i6 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v592[0], (unsigned int)(char)v367);
                                                      }
                                                      v49 = v451;
                                                      LODWORD(v149) = -1752948638;
                                                      if ( !v451 )
                                                        LODWORD(v149) = -1340685559;
                                                      for ( i7 = 693113538; ; i7 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( 1 )
                                                            {
                                                              v153 = i7;
                                                              v142 = v144;
                                                              if ( i7 <= 693113537 )
                                                                break;
                                                              if ( i7 > 1563511586 )
                                                              {
                                                                if ( i7 == 1563511587 )
                                                                {
                                                                  LOBYTE(v143) = v366 | 0x80;
                                                                  i7 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i7 = 1072704708;
                                                                  if ( !v367 )
                                                                    i7 = -1340685559;
                                                                }
                                                              }
                                                              else
                                                              {
                                                                v144 = (void *)v49;
                                                                i7 = (int)v149;
                                                                if ( v153 != 693113538 )
                                                                {
                                                                  v144 = v142;
                                                                  i7 = v153;
                                                                  if ( v153 == 1072704708 )
                                                                  {
                                                                    v592[0] = *(void **)v594;
                                                                    i7 = -1331101447;
                                                                    v144 = v142;
                                                                  }
                                                                }
                                                              }
                                                            }
                                                            if ( i7 <= -475423978 )
                                                              break;
                                                            if ( i7 == -475423977 )
                                                            {
                                                              v367 = (unsigned __int64)v616 >> 7;
                                                              v594 = (__int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v143);
                                                              i7 = 1696537547;
                                                              if ( v367 > 0x7F )
                                                                i7 = -1752948638;
                                                              v144 = (void *)v367;
                                                            }
                                                            else
                                                            {
                                                              i7 = -1340685559;
                                                            }
                                                          }
                                                          if ( i7 != -1752948638 )
                                                            break;
                                                          v616 = v144;
                                                          LOBYTE(v366) = (_BYTE)v144;
                                                          i7 = -475423977;
                                                          if ( (unsigned __int64)v144 >= 0x81 )
                                                            i7 = 1563511587;
                                                          LOBYTE(v143) = v366;
                                                        }
                                                        if ( i7 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v592[0], (unsigned int)(char)v367);
                                                        v144 = v142;
                                                      }
                                                      std::string::_M_append(v362, v450, v451);
                                                      v150 = -1747789055;
                                                    }
                                                    else
                                                    {
                                                      v150 = -905888113;
                                                      if ( !v345 )
                                                        v150 = -1747789055;
                                                    }
                                                  }
                                                  LODWORD(v149) = -1619953202;
                                                }
                                                else if ( (_DWORD)v149 == 735536065 )
                                                {
                                                  (**(void (__fastcall ***)(void **))mutex->__align)(&v616);
                                                  v366 = (unsigned __int64)v617;
                                                  v154 = 15683199;
                                                  while ( v154 != -1747789055 )
                                                  {
                                                    if ( v154 == -905888113 )
                                                    {
                                                      for ( i8 = 693113538; ; i8 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( i8 > 693113537 )
                                                            {
                                                              if ( i8 > 1563511586 )
                                                              {
                                                                if ( i8 == 1563511587 )
                                                                {
                                                                  LOBYTE(v149) = v346 | 0x80;
                                                                  i8 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i8 = 1072704708;
                                                                  if ( !v345 )
                                                                    i8 = -1340685559;
                                                                }
                                                              }
                                                              else if ( i8 == 693113538 )
                                                              {
                                                                i8 = -1752948638;
                                                                v49 = 10;
                                                              }
                                                              else
                                                              {
                                                                v594 = *(_QWORD *)v367;
                                                                i8 = -1331101447;
                                                              }
                                                            }
                                                            if ( i8 <= -475423978 )
                                                              break;
                                                            if ( i8 == -475423977 )
                                                            {
                                                              v345 = (unsigned __int64)v592[0] >> 7;
                                                              v367 = (unsigned __int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v149);
                                                              i8 = 1696537547;
                                                              if ( v345 > 0x7F )
                                                                i8 = -1752948638;
                                                              v49 = v345;
                                                            }
                                                            else
                                                            {
                                                              i8 = -1340685559;
                                                            }
                                                          }
                                                          if ( i8 != -1752948638 )
                                                            break;
                                                          v592[0] = (void *)v49;
                                                          v346 = v49;
                                                          i8 = -475423977;
                                                          if ( v49 >= 0x81 )
                                                            i8 = 1563511587;
                                                          LOBYTE(v149) = v346;
                                                        }
                                                        if ( i8 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v594, (unsigned int)(char)v345);
                                                      }
                                                      v49 = (unsigned __int64)v617;
                                                      LODWORD(v143) = -1752948638;
                                                      if ( !v617 )
                                                        LODWORD(v143) = -1340685559;
                                                      for ( i9 = 693113538; ; i9 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( 1 )
                                                            {
                                                              v157 = i9;
                                                              v149 = v144;
                                                              if ( i9 <= 693113537 )
                                                                break;
                                                              if ( i9 > 1563511586 )
                                                              {
                                                                if ( i9 == 1563511587 )
                                                                {
                                                                  LOBYTE(v142) = v346 | 0x80;
                                                                  i9 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i9 = 1072704708;
                                                                  if ( !v345 )
                                                                    i9 = -1340685559;
                                                                }
                                                              }
                                                              else
                                                              {
                                                                v144 = (void *)v49;
                                                                i9 = (int)v143;
                                                                if ( v157 != 693113538 )
                                                                {
                                                                  v144 = v149;
                                                                  i9 = v157;
                                                                  if ( v157 == 1072704708 )
                                                                  {
                                                                    v594 = *(_QWORD *)v367;
                                                                    i9 = -1331101447;
                                                                    v144 = v149;
                                                                  }
                                                                }
                                                              }
                                                            }
                                                            if ( i9 <= -475423978 )
                                                              break;
                                                            if ( i9 == -475423977 )
                                                            {
                                                              v345 = (unsigned __int64)v592[0] >> 7;
                                                              v367 = (unsigned __int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v142);
                                                              i9 = 1696537547;
                                                              if ( v345 > 0x7F )
                                                                i9 = -1752948638;
                                                              v144 = (void *)v345;
                                                            }
                                                            else
                                                            {
                                                              i9 = -1340685559;
                                                            }
                                                          }
                                                          if ( i9 != -1752948638 )
                                                            break;
                                                          v592[0] = v144;
                                                          v346 = (char)v144;
                                                          i9 = -475423977;
                                                          if ( (unsigned __int64)v144 >= 0x81 )
                                                            i9 = 1563511587;
                                                          LOBYTE(v142) = v346;
                                                        }
                                                        if ( i9 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v594, (unsigned int)(char)v345);
                                                        v144 = v149;
                                                      }
                                                      std::string::_M_append(v362, v616, v617);
                                                      v154 = -1747789055;
                                                    }
                                                    else
                                                    {
                                                      v154 = -905888113;
                                                      if ( !v366 )
                                                        v154 = -1747789055;
                                                    }
                                                  }
                                                  if ( v616 != &v618 )
                                                    operator delete(v616);
                                                  mutex->__align += 48;
                                                  LODWORD(v149) = 1270937927;
                                                }
                                                else
                                                {
                                                  LODWORD(v149) = 735536065;
                                                  if ( mutex->__align == *v338 )
                                                    LODWORD(v149) = 566702139;
                                                }
                                              }
                                              if ( (int)v149 <= -1152980463 )
                                                break;
                                              v365 = (char *)v338;
                                              *v338 = v340[1];
                                              LODWORD(v149) = 1270937927;
                                            }
                                            if ( (_DWORD)v149 != -1405111860 )
                                              break;
                                            mutex = (pthread_mutex_t *)v620;
                                            v338 = v619;
                                            v532 = v534;
                                            v533 = 0;
                                            v534[0] = 0;
                                            p_mutex = (pthread_mutex_t **)&v362;
                                            v362 = &v532;
                                            v340 = (void **)nptr + 1;
                                            v341 = (char *)v620;
                                            v620[0] = *((_QWORD *)&nptr[0] + 1);
                                          }
                                          *(_QWORD *)&nptr[0] = &off_7CA2848;
                                          if ( v450 != v452 )
                                            operator delete(v450);
                                          sub_570480E((char *)nptr + 8);
                                          v148 = 983097493;
                                        }
                                      }
                                      if ( v148 <= -1439742577 )
                                        break;
                                      if ( v148 == -1439742576 )
                                      {
                                        std::string::_M_assign(&v450, v360 + 72);
                                        v148 = -2129447168;
                                      }
                                      else if ( v148 == -1386401952 )
                                      {
LABEL_1283:
                                        v148 = -657443509;
                                      }
                                      else
                                      {
                                        v532 = v534;
                                        v158 = sub_56F9F18(&buf);
                                        std::string::_M_construct<char const*>(&v532, &buf, &buf + v158);
                                        v148 = 983097493;
                                      }
                                    }
                                    if ( v148 == -2129447168 )
                                      goto LABEL_1283;
                                    if ( v148 == -2111804588 )
                                    {
                                      v298 = (char *)nptr + 8;
                                      v331 = &v612;
                                      v145 = *(unsigned int *)(v361 + 32);
                                      v332 = *(_DWORD *)(v361 + 32);
                                      v313 = v361 + 32;
                                      v148 = 942904285;
                                    }
                                    else
                                    {
                                      v148 = -2129447168;
                                      v145 = 2855224720LL;
                                      if ( v342 )
                                        v148 = -1439742576;
                                    }
                                  }
                                }
                                sub_56A4A43(v302, 237, v301, "[FGESDK]", 2);
                              }
                              v141 = -569942109;
                              goto LABEL_1556;
                            }
                            if ( v141 == 1352552605 )
                            {
                              v325 = &v545;
                              v545 = (void *)0x5E061C1B07592F01LL;
                              v546 = 20;
                              v547 = 26;
                              v548 = 8;
                              v549 = 18;
                              v550 = 12;
                              v551 = 8;
                              v552 = 85;
                              v553 = 21;
                              v554 = 17;
                              v555 = 9;
                              v556 = 19;
                              v557 = 29;
                              v558 = 75;
                              v559 = 27;
                              v560 = 84;
                              v561 = 85;
                              v562 = 79;
                              v563 = 31;
                              v564 = 2;
                              v565 = 12;
                              v566 = 24;
                              v567 = 13;
                              v568 = 5;
                              v569 = 27;
                              v570 = 5;
                              v571 = 36;
                              LOBYTE(v46) = 121;
                              v572 = 121;
                              v573 = 25;
                              qmemcpy(v574, "==')", sizeof(v574));
                              v575 = 127;
                              qmemcpy(v576, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v576));
                              v577 = 26;
                              v578 = 93;
                              v579 = 93;
                              LOBYTE(v49) = 81;
                              v580 = 81;
                              v581 = 93;
                              v582 = 69;
                              v583 = 91;
                              v584 = 91;
                              v585 = 18;
                              qmemcpy(v586, "X^LP[ByQKHGO", sizeof(v586));
                              v587 = 14;
                              v588 = 71;
                              *(_QWORD *)&nptr[0] = v591;
                              i3 = 434048087;
                              v166 = &v589;
                              while ( (_DWORD)i3 != -1401140967 )
                              {
                                *v166++ = 0;
                                i3 = 434048087;
                                v46 = 2893826329LL;
                                if ( v166 == *(char **)&nptr[0] )
                                  i3 = 2893826329LL;
                              }
                              v141 = 1498882788;
                            }
                            else
                            {
                              if ( v141 != 1498882788 )
                              {
                                *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
                                *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
                                *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
                                LOBYTE(v49) = 79;
                                *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
                                v450 = (void *)0x29273D3D19792405LL;
                                v451 = 0x77753F30342B3D7FLL;
                                qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
                                v453 = (void *)0x5D515D5D1A585223LL;
                                v454 = 69;
                                v455 = 91;
                                v456 = 91;
                                v457 = 18;
                                qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
                                v459 = 14;
                                v460 = 71;
                                v612 = (unsigned __int64)v463;
                                v162 = 434048087;
                                v163 = &v461;
                                while ( v162 != -1401140967 )
                                {
                                  *v163++ = 0;
                                  v162 = 434048087;
                                  if ( v163 == (char *)v612 )
                                    v162 = -1401140967;
                                }
                                v609 = nptr;
                                LOBYTE(v367) = nptr[0];
                                for ( i10 = -675995946; ; i10 = 740258254 )
                                {
                                  while ( 1 )
                                  {
                                    while ( i10 > 673470317 )
                                    {
                                      if ( i10 > 810545848 )
                                      {
                                        if ( i10 == 810545849 )
                                        {
                                          ++v592[0];
                                        }
                                        else
                                        {
                                          v616 = v592;
                                          v592[0] = 0;
                                        }
                                        i10 = -495751738;
                                      }
                                      else if ( i10 == 673470318 )
                                      {
                                        v461 = 0;
                                        v462 = 0;
                                        *(_BYTE *)v609 = 0;
                                        i10 = -958661634;
                                      }
                                      else
                                      {
                                        *(_BYTE *)v612 = v594;
                                        i10 = 810545849;
                                      }
                                    }
                                    if ( i10 <= -675995947 )
                                      break;
                                    if ( i10 == -675995946 )
                                    {
                                      i10 = 1310473308;
                                      if ( (v367 & 1) == 0 )
                                        i10 = -958661634;
                                    }
                                    else
                                    {
                                      i10 = 673470318;
                                      if ( v592[0] < &qword_58 )
                                        i10 = -2012962271;
                                    }
                                  }
                                  if ( i10 != -2012962271 )
                                    break;
                                  LOBYTE(v594) = BYTE1(nptr[0])
                                               ^ *((_BYTE *)nptr + (unsigned __int64)v592[0] + 2)
                                               ^ (LOBYTE(v592[0]) + 1)
                                               ^ 0x58;
                                  v612 = (unsigned __int64)nptr + (unsigned __int64)v592[0] + 2;
                                }
                                v612 = 0x697B6F6C7A682F01LL;
                                qmemcpy(&v613, "-ffvheb$lt}w9x~uqww11dr`VEOM", 28);
                                v613.m256i_i16[14] = 2835;
                                v613.m256i_i8[30] = 75;
                                v616 = v615;
                                v170 = 1432350809;
                                v171 = &v613.m256i_i8[31];
                                while ( v170 != 1897238988 )
                                {
                                  *v171++ = 0;
                                  v170 = 1432350809;
                                  if ( v171 == v616 )
                                    v170 = 1897238988;
                                }
                                v594 = (__int64)&v612;
                                LOBYTE(v366) = v612;
                                for ( i11 = -1468158444; ; i11 = -537877447 )
                                {
                                  while ( 1 )
                                  {
                                    while ( i11 <= 678513966 )
                                    {
                                      if ( i11 > -537877448 )
                                      {
                                        if ( i11 == -537877447 )
                                        {
                                          i11 = 1181823369;
                                          if ( v367 < 0x25 )
                                            i11 = 897346759;
                                        }
                                        else
                                        {
                                          *((_BYTE *)v616 + v367++) = v345;
                                          i11 = -537877447;
                                        }
                                      }
                                      else if ( i11 == -2139562399 )
                                      {
                                        v616 = (char *)&v612 + 2;
                                        LOBYTE(v345) = BYTE1(v612)
                                                     ^ *((_BYTE *)&v612 + v367 + 2)
                                                     ^ ((-2 - (_BYTE)v609) & 0xC6 | ((_BYTE)v609 + 1) & 0x39)
                                                     ^ 0xE3;
                                        i11 = -416917990;
                                      }
                                      else
                                      {
                                        i11 = 883426621;
                                        if ( (v366 & 1) == 0 )
                                          i11 = 678513967;
                                      }
                                    }
                                    if ( i11 <= 897346758 )
                                      break;
                                    if ( i11 == 897346759 )
                                    {
                                      v609 = (void *)v367;
                                      i11 = -2139562399;
                                    }
                                    else
                                    {
                                      v613.m256i_i8[31] = 0;
                                      v614 = 0;
                                      *(_BYTE *)v594 = 0;
                                      i11 = 678513967;
                                    }
                                  }
                                  if ( i11 != 883426621 )
                                    break;
                                  v592[0] = &v367;
                                  v367 = 0;
                                }
                                sub_56A4A43((char *)nptr + 2, 249, (char *)&v612 + 2, "[FGESDK]", 2);
                                goto LABEL_1555;
                              }
                              v616 = &v545;
                              LOBYTE(v594) = (_BYTE)v545;
                              for ( i12 = -675995946; ; i12 = 740258254 )
                              {
                                while ( 1 )
                                {
                                  while ( i12 > 673470317 )
                                  {
                                    if ( i12 > 810545848 )
                                    {
                                      if ( i12 == 810545849 )
                                      {
                                        v609 = (char *)v609 + 1;
                                      }
                                      else
                                      {
                                        v612 = (unsigned __int64)&v609;
                                        v609 = 0;
                                      }
                                      i12 = -495751738;
                                    }
                                    else if ( i12 == 673470318 )
                                    {
                                      v589 = 0;
                                      v590 = 0;
                                      *(_BYTE *)v616 = 0;
                                      i12 = -958661634;
                                    }
                                    else
                                    {
                                      **(_BYTE **)&nptr[0] = v592[0];
                                      i12 = 810545849;
                                    }
                                  }
                                  if ( i12 <= -675995947 )
                                    break;
                                  if ( i12 == -675995946 )
                                  {
                                    i12 = 1310473308;
                                    if ( (v594 & 1) == 0 )
                                      i12 = -958661634;
                                  }
                                  else
                                  {
                                    i12 = 673470318;
                                    if ( (unsigned __int64)v609 < 0x58 )
                                      i12 = -2012962271;
                                  }
                                }
                                if ( i12 != -2012962271 )
                                  break;
                                LOBYTE(v592[0]) = BYTE1(v545)
                                                ^ *((_BYTE *)v609 + (_QWORD)&v545 + 2)
                                                ^ ((_BYTE)v609 + 1)
                                                ^ 0x58;
                                *(_QWORD *)&nptr[0] = (char *)v609 + (_QWORD)&v545 + 2;
                              }
                              v302 = (char *)&v545 + 2;
                              v324 = &v535;
                              v535 = 0x6674606375672F01LL;
                              LOBYTE(v46) = 116;
                              qmemcpy(v536, "\"iiygjm+c{rx6wqz~xx>>t\\~lLGB", sizeof(v536));
                              v537 = 6;
                              v538 = 72;
                              v539 = 83;
                              v540 = 3;
                              qmemcpy(v541, "LX@C", sizeof(v541));
                              *(_QWORD *)&nptr[0] = v544;
                              i3 = 53855480;
                              v175 = &v542;
                              while ( (_DWORD)i3 != -659242669 )
                              {
                                *v175++ = 0;
                                i3 = 53855480;
                                v46 = 3635724627LL;
                                if ( v175 == *(char **)&nptr[0] )
                                  i3 = 3635724627LL;
                              }
                              v609 = &v535;
                              LOBYTE(v345) = v535;
                              for ( i13 = -1694899481; ; i13 = -197543922 )
                              {
                                while ( 1 )
                                {
                                  while ( i13 > -344511993 )
                                  {
                                    if ( i13 > 1285572307 )
                                    {
                                      if ( i13 == 1285572308 )
                                      {
                                        LODWORD(v594) = v592[0];
                                        v612 = (unsigned __int64)&v535 + 2;
                                        *(_QWORD *)&nptr[0] = &v536[(unsigned __int64)v592[0] - 6];
                                        i13 = -344511992;
                                      }
                                      else
                                      {
                                        i3 = 0;
                                        v542 = 0;
                                        v543 = 0;
                                        *(_BYTE *)v609 = 0;
                                        i13 = -1732185182;
                                      }
                                    }
                                    else if ( i13 == -344511992 )
                                    {
                                      LOBYTE(v367) = **(_BYTE **)&nptr[0];
                                      i13 = -1809370947;
                                    }
                                    else
                                    {
                                      i13 = 1325648788;
                                      if ( v592[0] < (char *)&qword_28 + 2 )
                                        i13 = 1285572308;
                                    }
                                  }
                                  if ( i13 <= -1694899482 )
                                    break;
                                  if ( i13 == -1694899481 )
                                  {
                                    i13 = -1687380215;
                                    if ( (v345 & 1) == 0 )
                                      i13 = -1732185182;
                                  }
                                  else
                                  {
                                    v616 = v592;
                                    v592[0] = 0;
                                    i13 = -197543922;
                                  }
                                }
                                if ( i13 != -1809370947 )
                                  break;
                                LOBYTE(i3) = ((-2 - v594) & 0x92 | (v594 + 1) & 0x6D) ^ BYTE1(v535) ^ v367 ^ 0xB8;
                                v46 = v612;
                                *((_BYTE *)v592[0]++ + v612) = i3;
                              }
                              v301 = (char *)&v535 + 2;
                              v141 = 680291346;
                            }
                          }
                          if ( v141 > -1247314068 )
                            break;
                          if ( v141 == -2116383695 )
                          {
                            sub_56957EC(&v470, v532, &p_mutex);
                            v616 = &v618;
                            v164 = (unsigned __int64)v344;
                            std::string::_M_construct<char *>(
                              &v616,
                              *((_QWORD *)v344 + 8),
                              *((_QWORD *)v344 + 8) + *((_QWORD *)v344 + 9));
                            v612 = v164;
                            v613.m256i_i64[0] = (__int64)&v613.m256i_i64[2];
                            std::string::_M_construct<char *>(&v613, v616, (char *)v617 + (_QWORD)v616);
                            v165 = (char *)operator new(0x28u);
                            *(_QWORD *)v165 = v612;
                            *((_QWORD *)v165 + 1) = v165 + 24;
                            if ( (unsigned __int64 *)v613.m256i_i64[0] == &v613.m256i_u64[2] )
                            {
                              *(_OWORD *)(v165 + 24) = *(_OWORD *)&v613.m256i_u64[2];
                            }
                            else
                            {
                              *((_QWORD *)v165 + 1) = v613.m256i_i64[0];
                              *((_QWORD *)v165 + 3) = v613.m256i_i64[2];
                            }
                            *((_QWORD *)v165 + 2) = v613.m256i_i64[1];
                            v613.m256i_i64[0] = (__int64)&v613.m256i_i64[2];
                            v613.m256i_i64[1] = 0;
                            v613.m256i_i8[16] = 0;
                            v609 = v165;
                            *((_QWORD *)&v611 + 1) = sub_576A8DC;
                            *(_QWORD *)&v611 = &loc_576A8F0;
                            *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
                            *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
                            *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
                            *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
                            v450 = (void *)0x29273D3D19792405LL;
                            v451 = 0x77753F30342B3D7FLL;
                            qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
                            v453 = (void *)0x5D515D5D1A585223LL;
                            v454 = 69;
                            v455 = 91;
                            v456 = 91;
                            v457 = 18;
                            qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
                            v459 = 14;
                            v460 = 71;
                            v594 = (__int64)v463;
                            v177 = 434048087;
                            v178 = &v461;
                            while ( v177 != -1401140967 )
                            {
                              *v178++ = 0;
                              v177 = 434048087;
                              if ( v178 == (char *)v594 )
                                v177 = -1401140967;
                            }
                            v345 = (unsigned __int64)nptr;
                            LOBYTE(v341) = nptr[0];
                            for ( i14 = -675995946; ; i14 = 740258254 )
                            {
                              while ( 1 )
                              {
                                while ( i14 > 673470317 )
                                {
                                  if ( i14 > 810545848 )
                                  {
                                    if ( i14 == 810545849 )
                                    {
                                      ++v366;
                                    }
                                    else
                                    {
                                      v367 = (unsigned __int64)&v366;
                                      v366 = 0;
                                    }
                                    i14 = -495751738;
                                  }
                                  else if ( i14 == 673470318 )
                                  {
                                    v461 = 0;
                                    v462 = 0;
                                    *(_BYTE *)v345 = 0;
                                    i14 = -958661634;
                                  }
                                  else
                                  {
                                    *(_BYTE *)v594 = (_BYTE)v365;
                                    i14 = 810545849;
                                  }
                                }
                                if ( i14 <= -675995947 )
                                  break;
                                if ( i14 == -675995946 )
                                {
                                  i14 = 1310473308;
                                  if ( ((unsigned __int8)v341 & 1) == 0 )
                                    i14 = -958661634;
                                }
                                else
                                {
                                  i14 = 673470318;
                                  if ( v366 < 0x58 )
                                    i14 = -2012962271;
                                }
                              }
                              if ( i14 != -2012962271 )
                                break;
                              LOBYTE(v365) = BYTE1(nptr[0]) ^ *((_BYTE *)nptr + v366 + 2) ^ (v366 + 1) ^ 0x58;
                              v594 = (__int64)nptr + v366 + 2;
                            }
                            v594 = 0x125F595053572F01LL;
                            qmemcpy(v595, "@YSZR]JIZC@", sizeof(v595));
                            v596 = 6;
                            v597 = 29;
                            v598 = 0;
                            v599 = 77;
                            v600 = 71;
                            v601 = 77;
                            v602 = 12;
                            v603 = 23;
                            v604 = 11;
                            v605 = 75;
                            v367 = (unsigned __int64)&v608;
                            v180 = -769038311;
                            v181 = &v606;
                            while ( v180 != 1284930719 )
                            {
                              *v181++ = 0;
                              v180 = -769038311;
                              if ( v181 == (char *)v367 )
                                v180 = 1284930719;
                            }
                            v366 = (unsigned __int64)&v594;
                            LOBYTE(v340) = v594;
                            LODWORD(v182) = -962714612;
                            do
                            {
                              while ( 1 )
                              {
                                while ( 1 )
                                {
                                  while ( (int)v182 > -324670996 )
                                  {
                                    if ( (int)v182 > 307205468 )
                                    {
                                      if ( (_DWORD)v182 == 307205469 )
                                      {
                                        LODWORD(v341) = (_DWORD)v365;
                                        LODWORD(v182) = -324670995;
                                      }
                                      else if ( (_DWORD)v182 == 834103254 )
                                      {
                                        v606 = 0;
                                        v607 = 0;
                                        *(_BYTE *)v366 = 0;
                                        LODWORD(v182) = -1997885474;
                                      }
                                    }
                                    else if ( (_DWORD)v182 == -324670995 )
                                    {
                                      v365[(_QWORD)&v594 + 2] ^= ((_BYTE)v341 + 1) ^ BYTE1(v594) ^ 0x1B;
                                      v367 = (unsigned __int64)(v365 + 1);
                                      v182 = byte_28E9C53;
                                    }
                                    else if ( (_DWORD)v182 == (_DWORD)byte_28E9C53 )
                                    {
                                      v365 = (char *)v367;
                                      LODWORD(v182) = -794593716;
                                    }
                                  }
                                  if ( (int)v182 <= -962714613 )
                                    break;
                                  if ( (_DWORD)v182 == -962714612 )
                                  {
                                    LODWORD(v182) = -2083131433;
                                    if ( ((unsigned __int8)v340 & 1) == 0 )
                                      LODWORD(v182) = -1997885474;
                                  }
                                  else if ( (_DWORD)v182 == -794593716 )
                                  {
                                    LODWORD(v182) = 834103254;
                                    if ( (unsigned __int64)v365 < 0x1B )
                                      LODWORD(v182) = 307205469;
                                  }
                                }
                                if ( (_DWORD)v182 != -2083131433 )
                                  break;
                                v345 = (unsigned __int64)&v365;
                                v365 = 0;
                                LODWORD(v182) = -794593716;
                              }
                            }
                            while ( (_DWORD)v182 != -1997885474 );
                            sub_56A4A43((char *)nptr + 2, 260, (char *)&v594 + 2, "[FGESDK]", 1);
                            v183 = v344;
                            v344[96] = 1;
                            v184 = sub_56956B8();
                            v185 = v183;
                            v186 = v184;
                            v345 = (unsigned __int64)v307;
                            LOBYTE(v340) = *v307;
                            v187 = 578789870;
                            v188 = v308;
                            while ( 1 )
                            {
                              while ( 1 )
                              {
                                while ( v187 > 578789869 )
                                {
                                  if ( v187 > 1054713224 )
                                  {
                                    if ( v187 == 1054713225 )
                                    {
                                      v187 = 933373733;
                                      if ( v366 < 8 )
                                        v187 = 1409423605;
                                    }
                                    else
                                    {
                                      LODWORD(v365) = v366;
                                      v594 = v188;
                                      v187 = -186898055;
                                    }
                                  }
                                  else if ( v187 == 578789870 )
                                  {
                                    v187 = -2135764886;
                                    if ( ((unsigned __int8)v340 & 1) == 0 )
                                      v187 = 427872412;
                                  }
                                  else
                                  {
                                    v185[274] = 0;
                                    v185[275] = 0;
                                    *(_BYTE *)v345 = 0;
                                    v187 = 427872412;
                                  }
                                }
                                if ( v187 > 427872411 )
                                  break;
                                if ( v187 == -2135764886 )
                                {
                                  v367 = (unsigned __int64)&v366;
                                  v366 = 0;
                                  v187 = 1054713225;
                                }
                                else
                                {
                                  LOBYTE(v341) = ((_BYTE)v365 + 1) ^ v185[265] ^ *(_BYTE *)(v594 + v366) ^ 8;
                                  *(_QWORD *)&nptr[0] = v594 + v366;
                                  v187 = 436624164;
                                }
                              }
                              if ( v187 != 436624164 )
                                break;
                              **(_BYTE **)&nptr[0] = (_BYTE)v341;
                              ++v366;
                              v187 = 1054713225;
                            }
                            v592[0] = v593;
                            v189 = v185;
                            v190 = sub_56F9F18(v188);
                            std::string::_M_construct<char const*>(v592, v188, &v189[v190 + 266]);
                            v191 = v470;
                            v49 = (unsigned int)v471;
                            *(_QWORD *)&nptr[1] = 0;
                            if ( (_QWORD)v611 )
                            {
                              ((void (__fastcall *)(_OWORD *, void **, __int64))v611)(nptr, &v609, 2);
                              nptr[1] = v611;
                            }
                            sub_579DEA8(v186, v592, v191, (unsigned int)v49, nptr);
                            if ( *(_QWORD *)&nptr[1] )
                              (*(void (__fastcall **)(_OWORD *, _OWORD *, __int64))&nptr[1])(nptr, nptr, 3);
                            if ( v592[0] != v593 )
                              operator delete(v592[0]);
                            if ( (_QWORD)v611 )
                              ((void (__fastcall *)(void **, void **, __int64))v611)(&v609, &v609, 3);
                            if ( v616 != &v618 )
                              operator delete(v616);
                            if ( v470 != v472 )
                              operator delete(v470);
                            if ( v532 != v534 )
                              operator delete(v532);
LABEL_1555:
                            v141 = -230113714;
LABEL_1556:
                            v3 = v344;
                            continue;
                          }
                          if ( v141 == -1936494864 )
                          {
                            sub_56A4A43(v300, 245, v299, "[FGESDK]", 1);
                            v141 = -2116383695;
                            v3 = v344;
                          }
                          else
                          {
                            v323 = &v354;
                            v355 = 0;
                            v356 = 0;
                            v357 = &v355;
                            v358 = &v355;
                            v359 = 0;
                            v161 = (*(__int64 (__fastcall **)(_QWORD, unsigned __int64 *, __int64, _QWORD, __int64, void **))(*(_QWORD *)*v326 + 16LL))(
                                     *v326,
                                     &v354,
                                     v46,
                                     0,
                                     2282005025LL,
                                     v592);
                            v3 = v344;
                            v339 = v161;
                            v43 = v161 == 0;
                            v141 = 2011745991;
                            i3 = 3986692184LL;
                            if ( v43 )
                              v141 = -308275112;
                          }
                        }
                        if ( v141 != -1247314067 )
                          break;
                        v141 = -1601390004;
                        i3 = 1352552605;
                        if ( !*v326 )
                          v141 = 1352552605;
                      }
                      if ( v141 != -308275112 )
                        break;
                      v141 = 1066960081;
                      i3 = 4064853582LL;
                      if ( !v359 )
                        v141 = -230113714;
                    }
                    v137 = -839058132;
                  }
                }
                v48 = 1459318859;
              }
              else
              {
                if ( v48 != 575704836 )
                {
                  v311 = v620;
                  v69 = -1257953567;
                  v70 = v344;
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
                          while ( v69 <= -297893535 )
                          {
                            if ( v69 > -839058133 )
                            {
                              if ( v69 <= -478004355 )
                              {
                                if ( v69 != -839058132 )
                                {
                                  sub_56E5DF8(v348);
                                  v48 = -2007905915;
                                  goto LABEL_345;
                                }
                                v69 = 1095165697;
                              }
                              else if ( v69 == -478004354 )
                              {
                                v343 = v305 < 4;
                                v69 = 2031218905;
                              }
                              else
                              {
                                v69 = 1095165697;
                                i3 = 4190006973LL;
                                if ( (v70[96] & 1) == 0 )
                                  v69 = -104960323;
                              }
                            }
                            else if ( v69 > -1672859853 )
                            {
                              if ( v69 == -1672859852 )
                              {
                                v126 = v334;
                                *v334 = 1;
                                v126[1] = 47;
                                v126[2] = 85;
                                v126[3] = 74;
                                v126[4] = 76;
                                v126[5] = 5;
                                v126[6] = 65;
                                v126[7] = 74;
                                v126[8] = 86;
                                v126[9] = 93;
                                v126[10] = 81;
                                v126[11] = 10;
                                v126[12] = 2;
                                v126[13] = 8;
                                v126[14] = 95;
                                v126[15] = 6;
                                v127 = v126 + 16;
                                *(_QWORD *)&nptr[0] = v126 + 18;
                                v128 = 1244424498;
                                while ( v128 != -1410437110 )
                                {
                                  *v127++ = 0;
                                  v128 = 1244424498;
                                  if ( v127 == *(_BYTE **)&nptr[0] )
                                    v128 = -1410437110;
                                }
                                v129 = v334;
                                v612 = (unsigned __int64)v334;
                                LOBYTE(v535) = *v334;
                                v130 = v334 + 2;
                                for ( i15 = 626639548; ; i15 = 1914451914 )
                                {
                                  while ( 1 )
                                  {
                                    while ( i15 <= 1678190980 )
                                    {
                                      if ( i15 > 626639547 )
                                      {
                                        if ( i15 == 626639548 )
                                        {
                                          i15 = 1678190981;
                                          if ( (v535 & 1) == 0 )
                                            i15 = 1914451914;
                                        }
                                        else
                                        {
                                          LODWORD(v349) = v354;
                                          v545 = v130;
                                          *(_QWORD *)&nptr[0] = &v130[v354];
                                          i15 = -2137033712;
                                        }
                                      }
                                      else if ( i15 == -2137033712 )
                                      {
                                        *((_BYTE *)v545 + v354++) = (v349 + 1) ^ v129[1] ^ **(_BYTE **)&nptr[0] ^ 0xE;
                                        i15 = -125087914;
                                      }
                                      else
                                      {
LABEL_1066:
                                        i15 = 1806090338;
                                      }
                                    }
                                    if ( i15 > 1914451913 )
                                      break;
                                    if ( i15 == 1678190981 )
                                    {
                                      v485 = (unsigned __int64)&v354;
                                      v354 = 0;
                                      goto LABEL_1066;
                                    }
                                    i15 = 1986973541;
                                    if ( v354 < 0xE )
                                      i15 = 1088045697;
                                  }
                                  if ( i15 != 1986973541 )
                                    break;
                                  v129[16] = 0;
                                  v129[17] = 0;
                                  *(_BYTE *)v612 = 0;
                                }
                                sub_56A4A43(v304, 148, v130, "[FGESDK]", 2);
                                v69 = -575301484;
                                v70 = v344;
                              }
                              else
                              {
                                v335 = v620;
                                v334 = &v617;
                                v329 = &v348;
                                v306 = v310;
                                v69 = 1928266301;
                              }
                            }
                            else if ( v69 == -1977634016 )
                            {
                              v305 = *((_QWORD *)v333 + 1);
                              v69 = -478004354;
                            }
                            else
                            {
                              v328 = v335;
                              v69 = -297893534;
                            }
                          }
                          if ( v69 <= 1095165696 )
                            break;
                          if ( v69 > 1928266300 )
                          {
                            if ( v69 == 1928266301 )
                            {
                              v348 = v306;
                              sub_56E5AFC(v306);
                              v70 = v344;
                              v333 = v336;
                              v69 = -1977634016;
                              i3 = 2605311197LL;
                              if ( !*((_QWORD *)v336 + 1) )
                                v69 = -1689656099;
                            }
                            else
                            {
                              v69 = -413123324;
                              i3 = 2605311197LL;
                              if ( v343 )
                                v69 = -1689656099;
                            }
                          }
                          else if ( v69 == 1095165697 )
                          {
                            v69 = -575301484;
                          }
                          else
                          {
                            v71 = v303;
                            v545 = v309;
                            v46 = v303 - *v309;
                            *(_QWORD *)&nptr[0] = v46;
                            v72 = *((_QWORD *)v70 + 30);
                            for ( i16 = 563187957; ; i16 = -1643462965 )
                            {
                              while ( i16 > 134251944 )
                              {
                                if ( i16 == 134251945 )
                                {
                                  i16 = -1991102596;
                                  if ( (_BYTE)v485 )
                                    i16 = 1392767983;
                                }
                                else if ( i16 == 1392767983 )
                                {
                                  i16 = -1643462965;
                                  v46 = 0;
                                }
                                else
                                {
                                  LOBYTE(v485) = *(_QWORD *)&nptr[0] < v72;
                                  i16 = 134251945;
                                }
                              }
                              if ( i16 != -1991102596 )
                                break;
                              v46 = (__int64)v545;
                              *(_QWORD *)v545 = v71;
                              LOBYTE(v46) = 1;
                            }
                            v69 = -839058132;
                            i3 = 4271504012LL;
                            if ( (v46 & 1) != 0 )
                              v69 = -23463284;
                          }
                        }
                        if ( v69 != -297893534 )
                          break;
                        v132 = v335;
                        *v335 = 1;
                        v132[1] = 47;
                        v132[2] = 89;
                        v132[3] = 7;
                        v132[4] = 27;
                        v132[5] = 28;
                        v132[6] = 6;
                        v132[7] = 94;
                        v132[8] = 20;
                        v132[9] = 26;
                        v132[10] = 8;
                        v132[11] = 18;
                        v132[12] = 12;
                        v132[13] = 8;
                        v132[14] = 85;
                        v132[15] = 21;
                        v132[16] = 17;
                        v132[17] = 9;
                        v132[18] = 19;
                        v132[19] = 29;
                        LOBYTE(v3) = 75;
                        v132[20] = 75;
                        v132[21] = 27;
                        v132[22] = 84;
                        v132[23] = 85;
                        v132[24] = 79;
                        v132[25] = 31;
                        v132[26] = 2;
                        v132[27] = 12;
                        v132[28] = 24;
                        v132[29] = 13;
                        v132[30] = 5;
                        v132[31] = 27;
                        v132[32] = 5;
                        v132[33] = 36;
                        v132[34] = 121;
                        v132[35] = 25;
                        v132[36] = 61;
                        v132[37] = 61;
                        v132[38] = 39;
                        v132[39] = 41;
                        v132[40] = 127;
                        qmemcpy(v132 + 41, "=+40?uwvhhkkmln$*8$/.>&#RX", 26);
                        v132[67] = 26;
                        v132[68] = 93;
                        v132[69] = 93;
                        v132[70] = 81;
                        v132[71] = 93;
                        v132[72] = 69;
                        v132[73] = 91;
                        v132[74] = 91;
                        v132[75] = 18;
                        qmemcpy(v132 + 76, "X^LP[ByQKHGO", 12);
                        LOBYTE(v46) = 79;
                        v132[88] = 14;
                        v132[89] = 71;
                        v133 = v132 + 90;
                        *(_QWORD *)&nptr[0] = v132 + 92;
                        v134 = 434048087;
                        while ( v134 != -1401140967 )
                        {
                          *v133++ = 0;
                          v134 = 434048087;
                          v46 = 2893826329LL;
                          if ( v133 == *(_BYTE **)&nptr[0] )
                            v134 = -1401140967;
                        }
                        v135 = v335;
                        v485 = (unsigned __int64)v335;
                        LOBYTE(v349) = *v335;
                        for ( i3 = 3618971350LL; ; i3 = 740258254 )
                        {
                          while ( 1 )
                          {
                            while ( (int)i3 > 673470317 )
                            {
                              if ( (int)i3 > 810545848 )
                              {
                                if ( (_DWORD)i3 == 810545849 )
                                {
                                  ++v612;
                                }
                                else
                                {
                                  v545 = &v612;
                                  v612 = 0;
                                }
                                i3 = 3799215558LL;
                              }
                              else if ( (_DWORD)i3 == 673470318 )
                              {
                                v46 = 0;
                                v135[90] = 0;
                                v135[91] = 0;
                                *(_BYTE *)v485 = 0;
                                i3 = 3336305662LL;
                              }
                              else
                              {
                                v46 = *(_QWORD *)&nptr[0];
                                **(_BYTE **)&nptr[0] = v354;
                                i3 = 810545849;
                              }
                            }
                            if ( (int)i3 <= -675995947 )
                              break;
                            if ( (_DWORD)i3 == -675995946 )
                            {
                              i3 = 1310473308;
                              if ( (v349 & 1) == 0 )
                                i3 = 3336305662LL;
                            }
                            else
                            {
                              i3 = 673470318;
                              if ( v612 < 0x58 )
                                i3 = 2282005025LL;
                            }
                          }
                          if ( (_DWORD)i3 != -2012962271 )
                            break;
                          v46 = v612;
                          LOBYTE(v354) = v135[1] ^ v135[v612 + 2] ^ (v612 + 1) ^ 0x58;
                          *(_QWORD *)&nptr[0] = &v135[v612 + 2];
                        }
                        v304 = v135 + 2;
                        v327 = v334;
                        v69 = -1672859852;
                      }
                      if ( v69 != -104960323 )
                        break;
                      v136 = time(0);
                      v70 = v344;
                      v303 = v136;
                      v69 = 1769080040;
                    }
                    v315 = v620;
                    v326 = v70;
                    v74 = -1247314067;
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
LABEL_602:
                          while ( v74 > -230113715 )
                          {
                            if ( v74 <= 1352552604 )
                            {
                              if ( v74 == -230113714 )
                              {
                                std::_Rb_tree<int const,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int const>,std::allocator<std::pair<int const,std::string>>>::_M_erase(
                                  &v354,
                                  v356,
                                  v46,
                                  i3,
                                  2282005025LL,
                                  v592);
                              }
                              else
                              {
                                if ( v74 != 680291346 )
                                {
                                  v75 = (__int64 (__fastcall **)())v344;
                                  v322 = &v532;
                                  sub_570482E(&v349, &v354, v46, i3, 2282005025LL, v592);
                                  v314 = v620;
                                  v80 = 985969181;
                                  while ( 1 )
                                  {
                                    while ( 1 )
                                    {
                                      while ( v80 > -657443510 )
                                      {
                                        if ( v80 <= 983097492 )
                                        {
                                          if ( v80 == -657443509 )
                                          {
                                            v80 = -2111804588;
                                            v77 = 1206600332;
                                            if ( (char *)v361 == &v350 )
                                              v80 = 1206600332;
                                          }
                                          else if ( v80 == 924154336 )
                                          {
                                            v360 = sub_57041F8(v316, v336, v76, v77, v78, v79);
                                            v77 = (__int64)(v316 + 2);
                                            v342 = v360 != (_QWORD)(v316 + 2);
                                            v80 = -1990518946;
                                          }
                                          else
                                          {
                                            v609 = &v611;
                                            std::string::_M_construct<char *>(
                                              &v609,
                                              *(_QWORD *)(v313 + 8),
                                              *(_QWORD *)(v313 + 8) + *(_QWORD *)(v313 + 16));
                                            v75 = &off_7CA2800;
                                            v613.m256i_i32[0] = v332;
                                            v613.m256i_i64[1] = (__int64)&v613.m256i_i64[3];
                                            std::string::_M_construct<char *>(
                                              &v613.m256i_u64[1],
                                              v609,
                                              (char *)v609 + v610);
                                            sub_5704264(v298, &v612);
                                            v612 = (unsigned __int64)&off_7CA2800;
                                            if ( (unsigned __int64 *)v613.m256i_i64[1] != &v613.m256i_u64[3] )
                                              operator delete((void *)v613.m256i_i64[1]);
                                            if ( v609 != &v611 )
                                              operator delete(v609);
                                            v361 = std::_Rb_tree_increment(v361);
                                            v80 = -1386401952;
                                          }
                                        }
                                        else if ( v80 <= 1188221911 )
                                        {
                                          if ( v80 != 985969181 )
                                          {
                                            std::_Rb_tree<int const,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int const>,std::allocator<std::pair<int const,std::string>>>::_M_erase(
                                              &v349,
                                              v351,
                                              v76,
                                              v77,
                                              v78,
                                              v79);
                                            v321 = &v485;
                                            v485 = 0x5E061C1B07592F01LL;
                                            v486 = 20;
                                            v487 = 26;
                                            v488 = 8;
                                            v489 = 18;
                                            v490 = 12;
                                            v491 = 8;
                                            v492 = 85;
                                            v493 = 21;
                                            v494 = 17;
                                            v495 = 9;
                                            v496 = 19;
                                            v497 = 29;
                                            v498 = 75;
                                            v499 = 27;
                                            v500 = 84;
                                            v501 = 85;
                                            v502 = 79;
                                            v503 = 31;
                                            v504 = 2;
                                            v505 = 12;
                                            v506 = 24;
                                            v507 = 13;
                                            v508 = 5;
                                            v509 = 27;
                                            v510 = 5;
                                            v511 = 36;
                                            v512 = 121;
                                            v513 = 25;
                                            qmemcpy(v514, "==')", sizeof(v514));
                                            v515 = 127;
                                            qmemcpy(v516, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v516));
                                            v517 = 26;
                                            v518 = 93;
                                            v519 = 93;
                                            v520 = 81;
                                            v521 = 93;
                                            v522 = 69;
                                            v523 = 91;
                                            v524 = 91;
                                            v525 = 18;
                                            qmemcpy(v526, "X^LP[ByQKHGO", sizeof(v526));
                                            v527 = 14;
                                            v528 = 71;
                                            *(_QWORD *)&nptr[0] = v531;
                                            v93 = 434048087;
                                            v94 = &v529;
                                            v70 = v344;
                                            v46 = (__int64)&v485 + 2;
                                            while ( v93 != -1401140967 )
                                            {
                                              *v94++ = 0;
                                              v93 = 434048087;
                                              if ( v94 == *(char **)&nptr[0] )
                                                v93 = -1401140967;
                                            }
                                            v616 = &v485;
                                            LOBYTE(v594) = v485;
                                            for ( i17 = -675995946; ; i17 = 740258254 )
                                            {
                                              while ( 1 )
                                              {
                                                while ( i17 > 673470317 )
                                                {
                                                  if ( i17 > 810545848 )
                                                  {
                                                    if ( i17 == 810545849 )
                                                    {
                                                      v609 = (char *)v609 + 1;
                                                    }
                                                    else
                                                    {
                                                      v612 = (unsigned __int64)&v609;
                                                      v609 = 0;
                                                    }
                                                    i17 = -495751738;
                                                  }
                                                  else if ( i17 == 673470318 )
                                                  {
                                                    v529 = 0;
                                                    v530 = 0;
                                                    *(_BYTE *)v616 = 0;
                                                    i17 = -958661634;
                                                  }
                                                  else
                                                  {
                                                    **(_BYTE **)&nptr[0] = v592[0];
                                                    i17 = 810545849;
                                                  }
                                                }
                                                if ( i17 <= -675995947 )
                                                  break;
                                                if ( i17 == -675995946 )
                                                {
                                                  i17 = 1310473308;
                                                  if ( (v594 & 1) == 0 )
                                                    i17 = -958661634;
                                                }
                                                else
                                                {
                                                  i17 = 673470318;
                                                  if ( (unsigned __int64)v609 < 0x58 )
                                                    i17 = -2012962271;
                                                }
                                              }
                                              if ( i17 != -2012962271 )
                                                break;
                                              LOBYTE(v592[0]) = BYTE1(v485)
                                                              ^ *((_BYTE *)v609 + (_QWORD)&v485 + 2)
                                                              ^ ((_BYTE)v609 + 1)
                                                              ^ 0x58;
                                              *(_QWORD *)&nptr[0] = (char *)v609 + (_QWORD)&v485 + 2;
                                            }
                                            v300 = (char *)&v485 + 2;
                                            v320 = &v473;
                                            v473 = 0x5C1D57585B492F01LL;
                                            LOBYTE(v46) = 91;
                                            v474 = 74;
                                            v475 = 86;
                                            v476 = 87;
                                            v477 = 18;
                                            qmemcpy(v478, "AQFC[\\\tFNB", sizeof(v478));
                                            v479 = 23;
                                            v480 = 11;
                                            v481 = 75;
                                            *(_QWORD *)&nptr[0] = v484;
                                            i3 = 3160756352LL;
                                            v102 = &v482;
                                            while ( (_DWORD)i3 != -919254716 )
                                            {
                                              *v102++ = 0;
                                              i3 = 3160756352LL;
                                              v46 = 3375712580LL;
                                              if ( v102 == *(char **)&nptr[0] )
                                                i3 = 3375712580LL;
                                            }
                                            v609 = &v473;
                                            LOBYTE(v345) = v473;
                                            for ( i18 = 185907318; ; i18 = 1982752890 )
                                            {
                                              while ( 1 )
                                              {
                                                while ( i18 > 886249242 )
                                                {
                                                  if ( i18 > 1108581097 )
                                                  {
                                                    if ( i18 == 1108581098 )
                                                    {
                                                      i18 = 886249243;
                                                      i3 = 174559871;
                                                      if ( v592[0] < (char *)&dword_14 + 3 )
                                                        i18 = 174559871;
                                                    }
                                                    else
                                                    {
                                                      i3 = v612;
                                                      LOBYTE(v46) = v367;
                                                      *((_BYTE *)v592[0]++ + v612) = v367;
                                                      i18 = 1108581098;
                                                    }
                                                  }
                                                  else if ( i18 == 886249243 )
                                                  {
                                                    i3 = 0;
                                                    v482 = 0;
                                                    v483 = 0;
                                                    *(_BYTE *)v609 = 0;
                                                    i18 = 862340680;
                                                  }
                                                  else
                                                  {
                                                    v616 = v592;
                                                    v592[0] = 0;
                                                    i18 = 1108581098;
                                                  }
                                                }
                                                if ( i18 > 366432057 )
                                                  break;
                                                if ( i18 == 174559871 )
                                                {
                                                  LODWORD(v594) = v592[0];
                                                  v612 = (unsigned __int64)&v473 + 2;
                                                  *(void **)&nptr[0] = v592[0];
                                                  i18 = 366432058;
                                                }
                                                else
                                                {
                                                  i18 = 920627274;
                                                  if ( (v345 & 1) == 0 )
                                                    i18 = 862340680;
                                                }
                                              }
                                              if ( i18 != 366432058 )
                                                break;
                                              i3 = (unsigned int)v594;
                                              LOBYTE(i3) = v594 + 1;
                                              LOBYTE(v367) = (v594 + 1)
                                                           ^ BYTE1(v473)
                                                           ^ *(_BYTE *)(v612 + *(_QWORD *)&nptr[0])
                                                           ^ 0x17;
                                            }
                                            v299 = (char *)&v473 + 2;
                                            v74 = -1936494864;
                                            goto LABEL_602;
                                          }
                                          v80 = 1188221912;
                                          v77 = 2949622140LL;
                                          if ( !v353 )
                                            v80 = -1345345156;
                                        }
                                        else if ( v80 == 1188221912 )
                                        {
                                          v319 = &v361;
                                          v361 = v352;
                                          v318 = nptr;
                                          *(_QWORD *)&nptr[0] = &off_7CA2848;
                                          v77 = 0;
                                          memset((char *)nptr + 8, 0, 24);
                                          v450 = v452;
                                          v451 = 0;
                                          v452[0] = 0;
                                          v317 = &v360;
                                          v316 = v312;
                                          v80 = 924154336;
                                        }
                                        else
                                        {
                                          v330 = v620;
                                          for ( LODWORD(v81) = -1405111860; ; LODWORD(v81) = 139007939 )
                                          {
                                            while ( 1 )
                                            {
                                              while ( (int)v81 > 566702138 )
                                              {
                                                if ( (_DWORD)v81 == 566702139 )
                                                {
                                                  v345 = v451;
                                                  v82 = 15683199;
                                                  while ( v82 != -1747789055 )
                                                  {
                                                    if ( v82 == -905888113 )
                                                    {
                                                      for ( i19 = 693113538; ; i19 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( i19 > 693113537 )
                                                            {
                                                              if ( i19 > 1563511586 )
                                                              {
                                                                if ( i19 == 1563511587 )
                                                                {
                                                                  LOBYTE(v81) = v366 | 0x80;
                                                                  i19 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i19 = 1072704708;
                                                                  if ( !v367 )
                                                                    i19 = -1340685559;
                                                                }
                                                              }
                                                              else if ( i19 == 693113538 )
                                                              {
                                                                i19 = -1752948638;
                                                                v75 = (__int64 (__fastcall **)())&word_12;
                                                              }
                                                              else
                                                              {
                                                                v592[0] = *(void **)v594;
                                                                i19 = -1331101447;
                                                              }
                                                            }
                                                            if ( i19 <= -475423978 )
                                                              break;
                                                            if ( i19 == -475423977 )
                                                            {
                                                              v367 = (unsigned __int64)v616 >> 7;
                                                              v594 = (__int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v81);
                                                              i19 = 1696537547;
                                                              if ( v367 > 0x7F )
                                                                i19 = -1752948638;
                                                              v75 = (__int64 (__fastcall **)())v367;
                                                            }
                                                            else
                                                            {
                                                              i19 = -1340685559;
                                                            }
                                                          }
                                                          if ( i19 != -1752948638 )
                                                            break;
                                                          v616 = v75;
                                                          LOBYTE(v366) = (_BYTE)v75;
                                                          i19 = -475423977;
                                                          if ( (unsigned __int64)v75 >= 0x81 )
                                                            i19 = 1563511587;
                                                          LOBYTE(v81) = v366;
                                                        }
                                                        if ( i19 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v592[0], (unsigned int)(char)v367);
                                                      }
                                                      v75 = (__int64 (__fastcall **)())v451;
                                                      v84 = -1752948638;
                                                      if ( !v451 )
                                                        v84 = -1340685559;
                                                      for ( i20 = 693113538; ; i20 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( 1 )
                                                            {
                                                              v86 = i20;
                                                              v81 = v76;
                                                              if ( i20 <= 693113537 )
                                                                break;
                                                              if ( i20 > 1563511586 )
                                                              {
                                                                if ( i20 == 1563511587 )
                                                                {
                                                                  LOBYTE(v3) = v366 | 0x80;
                                                                  i20 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i20 = 1072704708;
                                                                  if ( !v367 )
                                                                    i20 = -1340685559;
                                                                }
                                                              }
                                                              else
                                                              {
                                                                v76 = v75;
                                                                i20 = v84;
                                                                if ( v86 != 693113538 )
                                                                {
                                                                  v76 = v81;
                                                                  i20 = v86;
                                                                  if ( v86 == 1072704708 )
                                                                  {
                                                                    v592[0] = *(void **)v594;
                                                                    i20 = -1331101447;
                                                                    v76 = v81;
                                                                  }
                                                                }
                                                              }
                                                            }
                                                            if ( i20 <= -475423978 )
                                                              break;
                                                            if ( i20 == -475423977 )
                                                            {
                                                              v367 = (unsigned __int64)v616 >> 7;
                                                              v594 = (__int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v3);
                                                              i20 = 1696537547;
                                                              if ( v367 > 0x7F )
                                                                i20 = -1752948638;
                                                              v76 = (void *)v367;
                                                            }
                                                            else
                                                            {
                                                              i20 = -1340685559;
                                                            }
                                                          }
                                                          if ( i20 != -1752948638 )
                                                            break;
                                                          v616 = v76;
                                                          LOBYTE(v366) = (_BYTE)v76;
                                                          i20 = -475423977;
                                                          if ( (unsigned __int64)v76 >= 0x81 )
                                                            i20 = 1563511587;
                                                          LOBYTE(v3) = v366;
                                                        }
                                                        if ( i20 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v592[0], (unsigned int)(char)v367);
                                                        v76 = v81;
                                                      }
                                                      std::string::_M_append(v362, v450, v451);
                                                      v82 = -1747789055;
                                                    }
                                                    else
                                                    {
                                                      v82 = -905888113;
                                                      if ( !v345 )
                                                        v82 = -1747789055;
                                                    }
                                                  }
                                                  LODWORD(v81) = -1619953202;
                                                }
                                                else if ( (_DWORD)v81 == 735536065 )
                                                {
                                                  (**(void (__fastcall ***)(void **))mutex->__align)(&v616);
                                                  v366 = (unsigned __int64)v617;
                                                  v87 = 15683199;
                                                  while ( v87 != -1747789055 )
                                                  {
                                                    if ( v87 == -905888113 )
                                                    {
                                                      for ( i21 = 693113538; ; i21 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( i21 > 693113537 )
                                                            {
                                                              if ( i21 > 1563511586 )
                                                              {
                                                                if ( i21 == 1563511587 )
                                                                {
                                                                  LOBYTE(v81) = v346 | 0x80;
                                                                  i21 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i21 = 1072704708;
                                                                  if ( !v345 )
                                                                    i21 = -1340685559;
                                                                }
                                                              }
                                                              else if ( i21 == 693113538 )
                                                              {
                                                                i21 = -1752948638;
                                                                v75 = (__int64 (__fastcall **)())(byte_9 + 1);
                                                              }
                                                              else
                                                              {
                                                                v594 = *(_QWORD *)v367;
                                                                i21 = -1331101447;
                                                              }
                                                            }
                                                            if ( i21 <= -475423978 )
                                                              break;
                                                            if ( i21 == -475423977 )
                                                            {
                                                              v345 = (unsigned __int64)v592[0] >> 7;
                                                              v367 = (unsigned __int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v81);
                                                              i21 = 1696537547;
                                                              if ( v345 > 0x7F )
                                                                i21 = -1752948638;
                                                              v75 = (__int64 (__fastcall **)())v345;
                                                            }
                                                            else
                                                            {
                                                              i21 = -1340685559;
                                                            }
                                                          }
                                                          if ( i21 != -1752948638 )
                                                            break;
                                                          v592[0] = v75;
                                                          v346 = (char)v75;
                                                          i21 = -475423977;
                                                          if ( (unsigned __int64)v75 >= 0x81 )
                                                            i21 = 1563511587;
                                                          LOBYTE(v81) = v346;
                                                        }
                                                        if ( i21 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v594, (unsigned int)(char)v345);
                                                      }
                                                      v75 = v617;
                                                      v89 = -1752948638;
                                                      if ( !v617 )
                                                        v89 = -1340685559;
                                                      for ( i22 = 693113538; ; i22 = -170651053 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            while ( 1 )
                                                            {
                                                              v91 = i22;
                                                              v81 = v76;
                                                              if ( i22 <= 693113537 )
                                                                break;
                                                              if ( i22 > 1563511586 )
                                                              {
                                                                if ( i22 == 1563511587 )
                                                                {
                                                                  LOBYTE(v3) = v346 | 0x80;
                                                                  i22 = -475423977;
                                                                }
                                                                else
                                                                {
                                                                  i22 = 1072704708;
                                                                  if ( !v345 )
                                                                    i22 = -1340685559;
                                                                }
                                                              }
                                                              else
                                                              {
                                                                v76 = v75;
                                                                i22 = v89;
                                                                if ( v91 != 693113538 )
                                                                {
                                                                  v76 = v81;
                                                                  i22 = v91;
                                                                  if ( v91 == 1072704708 )
                                                                  {
                                                                    v594 = *(_QWORD *)v367;
                                                                    i22 = -1331101447;
                                                                    v76 = v81;
                                                                  }
                                                                }
                                                              }
                                                            }
                                                            if ( i22 <= -475423978 )
                                                              break;
                                                            if ( i22 == -475423977 )
                                                            {
                                                              v345 = (unsigned __int64)v592[0] >> 7;
                                                              v367 = (unsigned __int64)&v362;
                                                              sub_56E41BA(v362, (unsigned int)(char)v3);
                                                              i22 = 1696537547;
                                                              if ( v345 > 0x7F )
                                                                i22 = -1752948638;
                                                              v76 = (void *)v345;
                                                            }
                                                            else
                                                            {
                                                              i22 = -1340685559;
                                                            }
                                                          }
                                                          if ( i22 != -1752948638 )
                                                            break;
                                                          v592[0] = v76;
                                                          v346 = (char)v76;
                                                          i22 = -475423977;
                                                          if ( (unsigned __int64)v76 >= 0x81 )
                                                            i22 = 1563511587;
                                                          LOBYTE(v3) = v346;
                                                        }
                                                        if ( i22 != -1331101447 )
                                                          break;
                                                        sub_56E41BA(v594, (unsigned int)(char)v345);
                                                        v76 = v81;
                                                      }
                                                      std::string::_M_append(v362, v616, v617);
                                                      v87 = -1747789055;
                                                    }
                                                    else
                                                    {
                                                      v87 = -905888113;
                                                      if ( !v366 )
                                                        v87 = -1747789055;
                                                    }
                                                  }
                                                  if ( v616 != &v618 )
                                                    operator delete(v616);
                                                  mutex->__align += 48;
                                                  LODWORD(v81) = 1270937927;
                                                }
                                                else
                                                {
                                                  LODWORD(v81) = 735536065;
                                                  if ( mutex->__align == *v338 )
                                                    LODWORD(v81) = 566702139;
                                                }
                                              }
                                              if ( (int)v81 <= -1152980463 )
                                                break;
                                              v365 = (char *)v338;
                                              *v338 = v340[1];
                                              LODWORD(v81) = 1270937927;
                                            }
                                            if ( (_DWORD)v81 != -1405111860 )
                                              break;
                                            mutex = (pthread_mutex_t *)v620;
                                            v338 = v619;
                                            v532 = v534;
                                            v533 = 0;
                                            v534[0] = 0;
                                            p_mutex = (pthread_mutex_t **)&v362;
                                            v362 = &v532;
                                            v340 = (void **)nptr + 1;
                                            v341 = (char *)v620;
                                            v620[0] = *((_QWORD *)&nptr[0] + 1);
                                          }
                                          *(_QWORD *)&nptr[0] = &off_7CA2848;
                                          if ( v450 != v452 )
                                            operator delete(v450);
                                          sub_570480E((char *)nptr + 8);
                                          v80 = 983097493;
                                        }
                                      }
                                      if ( v80 <= -1439742577 )
                                        break;
                                      if ( v80 == -1439742576 )
                                      {
                                        std::string::_M_assign(&v450, v360 + 72);
                                        v80 = -2129447168;
                                      }
                                      else if ( v80 == -1386401952 )
                                      {
LABEL_755:
                                        v80 = -657443509;
                                      }
                                      else
                                      {
                                        v532 = v534;
                                        v92 = sub_56F9F18(&buf);
                                        std::string::_M_construct<char const*>(&v532, &buf, &buf + v92);
                                        v80 = 983097493;
                                      }
                                    }
                                    if ( v80 == -2129447168 )
                                      goto LABEL_755;
                                    if ( v80 == -2111804588 )
                                    {
                                      v298 = (char *)nptr + 8;
                                      v331 = &v612;
                                      v77 = *(unsigned int *)(v361 + 32);
                                      v332 = *(_DWORD *)(v361 + 32);
                                      v313 = v361 + 32;
                                      v80 = 942904285;
                                    }
                                    else
                                    {
                                      v80 = -2129447168;
                                      v77 = 2855224720LL;
                                      if ( v342 )
                                        v80 = -1439742576;
                                    }
                                  }
                                }
                                sub_56A4A43(v302, 237, v301, "[FGESDK]", 2);
                              }
                              v74 = -569942109;
                              goto LABEL_1028;
                            }
                            if ( v74 == 1352552605 )
                            {
                              v325 = &v545;
                              v545 = (void *)0x5E061C1B07592F01LL;
                              v546 = 20;
                              v547 = 26;
                              v548 = 8;
                              v549 = 18;
                              v550 = 12;
                              v551 = 8;
                              v552 = 85;
                              v553 = 21;
                              v554 = 17;
                              v555 = 9;
                              v556 = 19;
                              v557 = 29;
                              LOBYTE(v3) = 75;
                              v558 = 75;
                              v559 = 27;
                              v560 = 84;
                              v561 = 85;
                              v562 = 79;
                              v563 = 31;
                              v564 = 2;
                              v565 = 12;
                              v566 = 24;
                              v567 = 13;
                              v568 = 5;
                              v569 = 27;
                              v570 = 5;
                              v571 = 36;
                              v572 = 121;
                              v573 = 25;
                              qmemcpy(v574, "==')", sizeof(v574));
                              v575 = 127;
                              qmemcpy(v576, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v576));
                              v577 = 26;
                              v578 = 93;
                              v579 = 93;
                              LOBYTE(v46) = 81;
                              v580 = 81;
                              v581 = 93;
                              v582 = 69;
                              v583 = 91;
                              v584 = 91;
                              v585 = 18;
                              qmemcpy(v586, "X^LP[ByQKHGO", sizeof(v586));
                              v587 = 14;
                              v588 = 71;
                              *(_QWORD *)&nptr[0] = v591;
                              i3 = 434048087;
                              v100 = &v589;
                              while ( (_DWORD)i3 != -1401140967 )
                              {
                                *v100++ = 0;
                                i3 = 434048087;
                                v46 = 2893826329LL;
                                if ( v100 == *(char **)&nptr[0] )
                                  i3 = 2893826329LL;
                              }
                              v74 = 1498882788;
                            }
                            else
                            {
                              if ( v74 != 1498882788 )
                              {
                                *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
                                *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
                                *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
                                *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
                                v450 = (void *)0x29273D3D19792405LL;
                                v451 = 0x77753F30342B3D7FLL;
                                qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
                                v453 = (void *)0x5D515D5D1A585223LL;
                                v454 = 69;
                                v455 = 91;
                                v456 = 91;
                                v457 = 18;
                                qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
                                v459 = 14;
                                v460 = 71;
                                v612 = (unsigned __int64)v463;
                                v96 = 434048087;
                                v97 = &v461;
                                while ( v96 != -1401140967 )
                                {
                                  *v97++ = 0;
                                  v96 = 434048087;
                                  if ( v97 == (char *)v612 )
                                    v96 = -1401140967;
                                }
                                v609 = nptr;
                                LOBYTE(v367) = nptr[0];
                                for ( i23 = -675995946; ; i23 = 740258254 )
                                {
                                  while ( 1 )
                                  {
                                    while ( i23 > 673470317 )
                                    {
                                      if ( i23 > 810545848 )
                                      {
                                        if ( i23 == 810545849 )
                                        {
                                          ++v592[0];
                                        }
                                        else
                                        {
                                          v616 = v592;
                                          v592[0] = 0;
                                        }
                                        i23 = -495751738;
                                      }
                                      else if ( i23 == 673470318 )
                                      {
                                        v461 = 0;
                                        v462 = 0;
                                        *(_BYTE *)v609 = 0;
                                        i23 = -958661634;
                                      }
                                      else
                                      {
                                        *(_BYTE *)v612 = v594;
                                        i23 = 810545849;
                                      }
                                    }
                                    if ( i23 <= -675995947 )
                                      break;
                                    if ( i23 == -675995946 )
                                    {
                                      i23 = 1310473308;
                                      if ( (v367 & 1) == 0 )
                                        i23 = -958661634;
                                    }
                                    else
                                    {
                                      i23 = 673470318;
                                      if ( v592[0] < &qword_58 )
                                        i23 = -2012962271;
                                    }
                                  }
                                  if ( i23 != -2012962271 )
                                    break;
                                  LOBYTE(v594) = BYTE1(nptr[0])
                                               ^ *((_BYTE *)nptr + (unsigned __int64)v592[0] + 2)
                                               ^ (LOBYTE(v592[0]) + 1)
                                               ^ 0x58;
                                  v612 = (unsigned __int64)nptr + (unsigned __int64)v592[0] + 2;
                                }
                                v612 = 0x697B6F6C7A682F01LL;
                                qmemcpy(&v613, "-ffvheb$lt}w9x~uqww11dr`VEOM", 28);
                                v613.m256i_i16[14] = 2835;
                                v613.m256i_i8[30] = 75;
                                v616 = v615;
                                v104 = 1432350809;
                                v105 = &v613.m256i_i8[31];
                                while ( v104 != 1897238988 )
                                {
                                  *v105++ = 0;
                                  v104 = 1432350809;
                                  if ( v105 == v616 )
                                    v104 = 1897238988;
                                }
                                v594 = (__int64)&v612;
                                LOBYTE(v366) = v612;
                                for ( i24 = -1468158444; ; i24 = -537877447 )
                                {
                                  while ( 1 )
                                  {
                                    while ( i24 <= 678513966 )
                                    {
                                      if ( i24 > -537877448 )
                                      {
                                        if ( i24 == -537877447 )
                                        {
                                          i24 = 1181823369;
                                          if ( v367 < 0x25 )
                                            i24 = 897346759;
                                        }
                                        else
                                        {
                                          *((_BYTE *)v616 + v367++) = v345;
                                          i24 = -537877447;
                                        }
                                      }
                                      else if ( i24 == -2139562399 )
                                      {
                                        v616 = (char *)&v612 + 2;
                                        LOBYTE(v345) = BYTE1(v612)
                                                     ^ *((_BYTE *)&v612 + v367 + 2)
                                                     ^ ((-2 - (_BYTE)v609) & 0xC6 | ((_BYTE)v609 + 1) & 0x39)
                                                     ^ 0xE3;
                                        i24 = -416917990;
                                      }
                                      else
                                      {
                                        i24 = 883426621;
                                        if ( (v366 & 1) == 0 )
                                          i24 = 678513967;
                                      }
                                    }
                                    if ( i24 <= 897346758 )
                                      break;
                                    if ( i24 == 897346759 )
                                    {
                                      v609 = (void *)v367;
                                      i24 = -2139562399;
                                    }
                                    else
                                    {
                                      v613.m256i_i8[31] = 0;
                                      v614 = 0;
                                      *(_BYTE *)v594 = 0;
                                      i24 = 678513967;
                                    }
                                  }
                                  if ( i24 != 883426621 )
                                    break;
                                  v592[0] = &v367;
                                  v367 = 0;
                                }
                                sub_56A4A43((char *)nptr + 2, 249, (char *)&v612 + 2, "[FGESDK]", 2);
                                goto LABEL_1027;
                              }
                              v616 = &v545;
                              LOBYTE(v594) = (_BYTE)v545;
                              for ( i25 = -675995946; ; i25 = 740258254 )
                              {
                                while ( 1 )
                                {
                                  while ( i25 > 673470317 )
                                  {
                                    if ( i25 > 810545848 )
                                    {
                                      if ( i25 == 810545849 )
                                      {
                                        v609 = (char *)v609 + 1;
                                      }
                                      else
                                      {
                                        v612 = (unsigned __int64)&v609;
                                        v609 = 0;
                                      }
                                      i25 = -495751738;
                                    }
                                    else if ( i25 == 673470318 )
                                    {
                                      v589 = 0;
                                      v590 = 0;
                                      *(_BYTE *)v616 = 0;
                                      i25 = -958661634;
                                    }
                                    else
                                    {
                                      **(_BYTE **)&nptr[0] = v592[0];
                                      i25 = 810545849;
                                    }
                                  }
                                  if ( i25 <= -675995947 )
                                    break;
                                  if ( i25 == -675995946 )
                                  {
                                    i25 = 1310473308;
                                    if ( (v594 & 1) == 0 )
                                      i25 = -958661634;
                                  }
                                  else
                                  {
                                    i25 = 673470318;
                                    if ( (unsigned __int64)v609 < 0x58 )
                                      i25 = -2012962271;
                                  }
                                }
                                if ( i25 != -2012962271 )
                                  break;
                                LOBYTE(v592[0]) = BYTE1(v545)
                                                ^ *((_BYTE *)v609 + (_QWORD)&v545 + 2)
                                                ^ ((_BYTE)v609 + 1)
                                                ^ 0x58;
                                *(_QWORD *)&nptr[0] = (char *)v609 + (_QWORD)&v545 + 2;
                              }
                              v302 = (char *)&v545 + 2;
                              v324 = &v535;
                              v535 = 0x6674606375672F01LL;
                              LOBYTE(v46) = 116;
                              qmemcpy(v536, "\"iiygjm+c{rx6wqz~xx>>t\\~lLGB", sizeof(v536));
                              v537 = 6;
                              v538 = 72;
                              v539 = 83;
                              v540 = 3;
                              qmemcpy(v541, "LX@C", sizeof(v541));
                              *(_QWORD *)&nptr[0] = v544;
                              i3 = 53855480;
                              v109 = &v542;
                              while ( (_DWORD)i3 != -659242669 )
                              {
                                *v109++ = 0;
                                i3 = 53855480;
                                v46 = 3635724627LL;
                                if ( v109 == *(char **)&nptr[0] )
                                  i3 = 3635724627LL;
                              }
                              v609 = &v535;
                              LOBYTE(v345) = v535;
                              for ( i26 = -1694899481; ; i26 = -197543922 )
                              {
                                while ( 1 )
                                {
                                  while ( i26 > -344511993 )
                                  {
                                    if ( i26 > 1285572307 )
                                    {
                                      if ( i26 == 1285572308 )
                                      {
                                        LODWORD(v594) = v592[0];
                                        v612 = (unsigned __int64)&v535 + 2;
                                        *(_QWORD *)&nptr[0] = &v536[(unsigned __int64)v592[0] - 6];
                                        i26 = -344511992;
                                      }
                                      else
                                      {
                                        i3 = 0;
                                        v542 = 0;
                                        v543 = 0;
                                        *(_BYTE *)v609 = 0;
                                        i26 = -1732185182;
                                      }
                                    }
                                    else if ( i26 == -344511992 )
                                    {
                                      LOBYTE(v367) = **(_BYTE **)&nptr[0];
                                      i26 = -1809370947;
                                    }
                                    else
                                    {
                                      i26 = 1325648788;
                                      if ( v592[0] < (char *)&qword_28 + 2 )
                                        i26 = 1285572308;
                                    }
                                  }
                                  if ( i26 <= -1694899482 )
                                    break;
                                  if ( i26 == -1694899481 )
                                  {
                                    i26 = -1687380215;
                                    if ( (v345 & 1) == 0 )
                                      i26 = -1732185182;
                                  }
                                  else
                                  {
                                    v616 = v592;
                                    v592[0] = 0;
                                    i26 = -197543922;
                                  }
                                }
                                if ( i26 != -1809370947 )
                                  break;
                                LOBYTE(i3) = ((-2 - v594) & 0x92 | (v594 + 1) & 0x6D) ^ BYTE1(v535) ^ v367 ^ 0xB8;
                                v46 = v612;
                                *((_BYTE *)v592[0]++ + v612) = i3;
                              }
                              v301 = (char *)&v535 + 2;
                              v74 = 680291346;
                            }
                          }
                          if ( v74 > -1247314068 )
                            break;
                          if ( v74 == -2116383695 )
                          {
                            sub_56957EC(&v470, v532, &p_mutex);
                            v616 = &v618;
                            v98 = (unsigned __int64)v344;
                            std::string::_M_construct<char *>(
                              &v616,
                              *((_QWORD *)v344 + 8),
                              *((_QWORD *)v344 + 8) + *((_QWORD *)v344 + 9));
                            v612 = v98;
                            v613.m256i_i64[0] = (__int64)&v613.m256i_i64[2];
                            std::string::_M_construct<char *>(&v613, v616, (char *)v617 + (_QWORD)v616);
                            v99 = (char *)operator new(0x28u);
                            *(_QWORD *)v99 = v612;
                            *((_QWORD *)v99 + 1) = v99 + 24;
                            if ( (unsigned __int64 *)v613.m256i_i64[0] == &v613.m256i_u64[2] )
                            {
                              *(_OWORD *)(v99 + 24) = *(_OWORD *)&v613.m256i_u64[2];
                            }
                            else
                            {
                              *((_QWORD *)v99 + 1) = v613.m256i_i64[0];
                              *((_QWORD *)v99 + 3) = v613.m256i_i64[2];
                            }
                            *((_QWORD *)v99 + 2) = v613.m256i_i64[1];
                            v613.m256i_i64[0] = (__int64)&v613.m256i_i64[2];
                            v613.m256i_i64[1] = 0;
                            v613.m256i_i8[16] = 0;
                            v609 = v99;
                            *((_QWORD *)&v611 + 1) = sub_576A8DC;
                            *(_QWORD *)&v611 = &loc_576A8F0;
                            *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
                            *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
                            *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
                            *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
                            v450 = (void *)0x29273D3D19792405LL;
                            v451 = 0x77753F30342B3D7FLL;
                            qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
                            v453 = (void *)0x5D515D5D1A585223LL;
                            v454 = 69;
                            v455 = 91;
                            v456 = 91;
                            v457 = 18;
                            qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
                            v459 = 14;
                            v460 = 71;
                            v594 = (__int64)v463;
                            v111 = 434048087;
                            v112 = &v461;
                            while ( v111 != -1401140967 )
                            {
                              *v112++ = 0;
                              v111 = 434048087;
                              if ( v112 == (char *)v594 )
                                v111 = -1401140967;
                            }
                            v345 = (unsigned __int64)nptr;
                            LOBYTE(v341) = nptr[0];
                            for ( i27 = -675995946; ; i27 = 740258254 )
                            {
                              while ( 1 )
                              {
                                while ( i27 > 673470317 )
                                {
                                  if ( i27 > 810545848 )
                                  {
                                    if ( i27 == 810545849 )
                                    {
                                      ++v366;
                                    }
                                    else
                                    {
                                      v367 = (unsigned __int64)&v366;
                                      v366 = 0;
                                    }
                                    i27 = -495751738;
                                  }
                                  else if ( i27 == 673470318 )
                                  {
                                    v461 = 0;
                                    v462 = 0;
                                    *(_BYTE *)v345 = 0;
                                    i27 = -958661634;
                                  }
                                  else
                                  {
                                    *(_BYTE *)v594 = (_BYTE)v365;
                                    i27 = 810545849;
                                  }
                                }
                                if ( i27 <= -675995947 )
                                  break;
                                if ( i27 == -675995946 )
                                {
                                  i27 = 1310473308;
                                  if ( ((unsigned __int8)v341 & 1) == 0 )
                                    i27 = -958661634;
                                }
                                else
                                {
                                  i27 = 673470318;
                                  if ( v366 < 0x58 )
                                    i27 = -2012962271;
                                }
                              }
                              if ( i27 != -2012962271 )
                                break;
                              LOBYTE(v365) = BYTE1(nptr[0]) ^ *((_BYTE *)nptr + v366 + 2) ^ (v366 + 1) ^ 0x58;
                              v594 = (__int64)nptr + v366 + 2;
                            }
                            v594 = 0x125F595053572F01LL;
                            qmemcpy(v595, "@YSZR]JIZC@", sizeof(v595));
                            v596 = 6;
                            v597 = 29;
                            v598 = 0;
                            v599 = 77;
                            v600 = 71;
                            v601 = 77;
                            v602 = 12;
                            v603 = 23;
                            v604 = 11;
                            v605 = 75;
                            v367 = (unsigned __int64)&v608;
                            v114 = -769038311;
                            v115 = &v606;
                            while ( v114 != 1284930719 )
                            {
                              *v115++ = 0;
                              v114 = -769038311;
                              if ( v115 == (char *)v367 )
                                v114 = 1284930719;
                            }
                            v366 = (unsigned __int64)&v594;
                            LOBYTE(v340) = v594;
                            LODWORD(v116) = -962714612;
                            do
                            {
                              while ( 1 )
                              {
                                while ( 1 )
                                {
                                  while ( (int)v116 > -324670996 )
                                  {
                                    if ( (int)v116 > 307205468 )
                                    {
                                      if ( (_DWORD)v116 == 307205469 )
                                      {
                                        LODWORD(v341) = (_DWORD)v365;
                                        LODWORD(v116) = -324670995;
                                      }
                                      else if ( (_DWORD)v116 == 834103254 )
                                      {
                                        v606 = 0;
                                        v607 = 0;
                                        *(_BYTE *)v366 = 0;
                                        LODWORD(v116) = -1997885474;
                                      }
                                    }
                                    else if ( (_DWORD)v116 == -324670995 )
                                    {
                                      v365[(_QWORD)&v594 + 2] ^= ((_BYTE)v341 + 1) ^ BYTE1(v594) ^ 0x1B;
                                      v367 = (unsigned __int64)(v365 + 1);
                                      v116 = byte_28E9C53;
                                    }
                                    else if ( (_DWORD)v116 == (_DWORD)byte_28E9C53 )
                                    {
                                      v365 = (char *)v367;
                                      LODWORD(v116) = -794593716;
                                    }
                                  }
                                  if ( (int)v116 <= -962714613 )
                                    break;
                                  if ( (_DWORD)v116 == -962714612 )
                                  {
                                    LODWORD(v116) = -2083131433;
                                    if ( ((unsigned __int8)v340 & 1) == 0 )
                                      LODWORD(v116) = -1997885474;
                                  }
                                  else if ( (_DWORD)v116 == -794593716 )
                                  {
                                    LODWORD(v116) = 834103254;
                                    if ( (unsigned __int64)v365 < 0x1B )
                                      LODWORD(v116) = 307205469;
                                  }
                                }
                                if ( (_DWORD)v116 != -2083131433 )
                                  break;
                                v345 = (unsigned __int64)&v365;
                                v365 = 0;
                                LODWORD(v116) = -794593716;
                              }
                            }
                            while ( (_DWORD)v116 != -1997885474 );
                            sub_56A4A43((char *)nptr + 2, 260, (char *)&v594 + 2, "[FGESDK]", 1);
                            v117 = v344;
                            v344[96] = 1;
                            v118 = sub_56956B8();
                            v119 = v117;
                            v3 = (char *)v118;
                            v345 = (unsigned __int64)v307;
                            LOBYTE(v340) = *v307;
                            v120 = 578789870;
                            v121 = v308;
                            while ( 1 )
                            {
                              while ( 1 )
                              {
                                while ( v120 > 578789869 )
                                {
                                  if ( v120 > 1054713224 )
                                  {
                                    if ( v120 == 1054713225 )
                                    {
                                      v120 = 933373733;
                                      if ( v366 < 8 )
                                        v120 = 1409423605;
                                    }
                                    else
                                    {
                                      LODWORD(v365) = v366;
                                      v594 = v121;
                                      v120 = -186898055;
                                    }
                                  }
                                  else if ( v120 == 578789870 )
                                  {
                                    v120 = -2135764886;
                                    if ( ((unsigned __int8)v340 & 1) == 0 )
                                      v120 = 427872412;
                                  }
                                  else
                                  {
                                    v119[274] = 0;
                                    v119[275] = 0;
                                    *(_BYTE *)v345 = 0;
                                    v120 = 427872412;
                                  }
                                }
                                if ( v120 > 427872411 )
                                  break;
                                if ( v120 == -2135764886 )
                                {
                                  v367 = (unsigned __int64)&v366;
                                  v366 = 0;
                                  v120 = 1054713225;
                                }
                                else
                                {
                                  LOBYTE(v341) = ((_BYTE)v365 + 1) ^ v119[265] ^ *(_BYTE *)(v594 + v366) ^ 8;
                                  *(_QWORD *)&nptr[0] = v594 + v366;
                                  v120 = 436624164;
                                }
                              }
                              if ( v120 != 436624164 )
                                break;
                              **(_BYTE **)&nptr[0] = (_BYTE)v341;
                              ++v366;
                              v120 = 1054713225;
                            }
                            v592[0] = v593;
                            v122 = v119;
                            v123 = sub_56F9F18(v121);
                            std::string::_M_construct<char const*>(v592, v121, &v122[v123 + 266]);
                            v124 = v470;
                            v125 = v471;
                            *(_QWORD *)&nptr[1] = 0;
                            if ( (_QWORD)v611 )
                            {
                              ((void (__fastcall *)(_OWORD *, void **, __int64))v611)(nptr, &v609, 2);
                              nptr[1] = v611;
                            }
                            sub_579DEA8(v3, v592, v124, v125, nptr);
                            if ( *(_QWORD *)&nptr[1] )
                              (*(void (__fastcall **)(_OWORD *, _OWORD *, __int64))&nptr[1])(nptr, nptr, 3);
                            if ( v592[0] != v593 )
                              operator delete(v592[0]);
                            if ( (_QWORD)v611 )
                              ((void (__fastcall *)(void **, void **, __int64))v611)(&v609, &v609, 3);
                            if ( v616 != &v618 )
                              operator delete(v616);
                            if ( v470 != v472 )
                              operator delete(v470);
                            if ( v532 != v534 )
                              operator delete(v532);
LABEL_1027:
                            v74 = -230113714;
LABEL_1028:
                            v70 = v344;
                            continue;
                          }
                          if ( v74 == -1936494864 )
                          {
                            sub_56A4A43(v300, 245, v299, "[FGESDK]", 1);
                            v74 = -2116383695;
                            v70 = v344;
                          }
                          else
                          {
                            v323 = &v354;
                            v355 = 0;
                            v356 = 0;
                            v357 = &v355;
                            v358 = &v355;
                            v359 = 0;
                            v95 = (*(__int64 (__fastcall **)(_QWORD, unsigned __int64 *, __int64, _QWORD, __int64, void **))(*(_QWORD *)*v326 + 16LL))(
                                    *v326,
                                    &v354,
                                    v46,
                                    0,
                                    2282005025LL,
                                    v592);
                            v70 = v344;
                            v339 = v95;
                            v43 = v95 == 0;
                            v74 = 2011745991;
                            i3 = 3986692184LL;
                            if ( v43 )
                              v74 = -308275112;
                          }
                        }
                        if ( v74 != -1247314067 )
                          break;
                        v74 = -1601390004;
                        i3 = 1352552605;
                        if ( !*v326 )
                          v74 = 1352552605;
                      }
                      if ( v74 != -308275112 )
                        break;
                      v74 = 1066960081;
                      i3 = 4064853582LL;
                      if ( !v359 )
                        v74 = -230113714;
                    }
                    v69 = -839058132;
                  }
                }
                i3 = (__int64)v278;
                *v278 = v279;
                v48 = 5790775;
                if ( v347 == (_QWORD *)(v290 + 2) )
                  v48 = -413531233;
              }
            }
            else if ( v48 <= 1153267324 )
            {
              if ( v48 == 946759078 )
              {
                v485 = (unsigned __int64)v296;
                LOBYTE(v612) = *v296;
                v66 = -2054724375;
                while ( v66 != 1928391394 )
                {
                  if ( v66 == 332328591 )
                  {
                    *(_BYTE *)v485 = 1;
                    v545 = &v554;
                    v67 = sub_56F9F18("emptyToken");
                    std::string::_M_construct<char const*>(&v545, "emptyToken", &aEmptytoken[v67]);
                    sub_56DB6BA(nptr, &v545);
                    if ( v545 != &v554 )
                      operator delete(v545);
                    v68 = sub_56DB816();
                    sub_5B98606(v68, nptr, 1);
                    if ( v468 != v294 )
                      operator delete(v468);
                    v49 = 1831282351;
                    if ( v466 != v295 )
                      operator delete(v466);
                    if ( v464 != v465 )
                      operator delete(v464);
                    if ( v453 != &v458[4] )
                      operator delete(v453);
                    if ( v450 != v452 )
                      operator delete(v450);
                    if ( *(_OWORD **)&nptr[0] != &nptr[1] )
                      operator delete(*(void **)&nptr[0]);
                    v66 = 1928391394;
                  }
                  else
                  {
                    v66 = 1928391394;
                    i3 = 332328591;
                    if ( (v612 & 1) == 0 )
                      v66 = 332328591;
                  }
                }
                v48 = -562262634;
              }
              else
              {
                sub_56A4A43(v282, 102, v281, "[FGESDK]", 1);
                v48 = -706512396;
              }
            }
            else if ( v48 == 1153267325 )
            {
              v48 = 513076159;
              if ( !*v283 )
                v48 = 1550342641;
            }
            else
            {
              if ( v48 == 1381601663 )
              {
                v311 = v620;
                v203 = -1257953567;
                v204 = v344;
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( v203 <= -297893535 )
                        {
                          if ( v203 > -839058133 )
                          {
                            if ( v203 <= -478004355 )
                            {
                              if ( v203 != -839058132 )
                              {
                                sub_56E5DF8(v348);
                                v48 = 1385966020;
                                goto LABEL_345;
                              }
                              v203 = 1095165697;
                            }
                            else if ( v203 == -478004354 )
                            {
                              v343 = v305 < 4;
                              v203 = 2031218905;
                            }
                            else
                            {
                              v203 = 1095165697;
                              i3 = 4190006973LL;
                              if ( (v204[96] & 1) == 0 )
                                v203 = -104960323;
                            }
                          }
                          else if ( v203 > -1672859853 )
                          {
                            if ( v203 == -1672859852 )
                            {
                              v260 = v334;
                              *v334 = 1;
                              v260[1] = 47;
                              v260[2] = 85;
                              v260[3] = 74;
                              v260[4] = 76;
                              v260[5] = 5;
                              v260[6] = 65;
                              v260[7] = 74;
                              v260[8] = 86;
                              v260[9] = 93;
                              v260[10] = 81;
                              v260[11] = 10;
                              v260[12] = 2;
                              v260[13] = 8;
                              v260[14] = 95;
                              v260[15] = 6;
                              v261 = v260 + 16;
                              *(_QWORD *)&nptr[0] = v260 + 18;
                              v262 = 1244424498;
                              while ( v262 != -1410437110 )
                              {
                                *v261++ = 0;
                                v262 = 1244424498;
                                if ( v261 == *(_BYTE **)&nptr[0] )
                                  v262 = -1410437110;
                              }
                              v263 = v334;
                              v612 = (unsigned __int64)v334;
                              LOBYTE(v535) = *v334;
                              v264 = v334 + 2;
                              for ( i28 = 626639548; ; i28 = 1914451914 )
                              {
                                while ( 1 )
                                {
                                  while ( i28 <= 1678190980 )
                                  {
                                    if ( i28 > 626639547 )
                                    {
                                      if ( i28 == 626639548 )
                                      {
                                        i28 = 1678190981;
                                        if ( (v535 & 1) == 0 )
                                          i28 = 1914451914;
                                      }
                                      else
                                      {
                                        LODWORD(v349) = v354;
                                        v545 = v264;
                                        *(_QWORD *)&nptr[0] = &v264[v354];
                                        i28 = -2137033712;
                                      }
                                    }
                                    else if ( i28 == -2137033712 )
                                    {
                                      *((_BYTE *)v545 + v354++) = (v349 + 1) ^ v263[1] ^ **(_BYTE **)&nptr[0] ^ 0xE;
                                      i28 = -125087914;
                                    }
                                    else
                                    {
LABEL_2122:
                                      i28 = 1806090338;
                                    }
                                  }
                                  if ( i28 > 1914451913 )
                                    break;
                                  if ( i28 == 1678190981 )
                                  {
                                    v485 = (unsigned __int64)&v354;
                                    v354 = 0;
                                    goto LABEL_2122;
                                  }
                                  i28 = 1986973541;
                                  if ( v354 < 0xE )
                                    i28 = 1088045697;
                                }
                                if ( i28 != 1986973541 )
                                  break;
                                v263[16] = 0;
                                v263[17] = 0;
                                *(_BYTE *)v612 = 0;
                              }
                              sub_56A4A43(v304, 148, v264, "[FGESDK]", 2);
                              v203 = -575301484;
                              v204 = v344;
                            }
                            else
                            {
                              v335 = v620;
                              v334 = &v617;
                              v329 = &v348;
                              v306 = v310;
                              v203 = 1928266301;
                            }
                          }
                          else if ( v203 == -1977634016 )
                          {
                            v305 = *((_QWORD *)v333 + 1);
                            v203 = -478004354;
                          }
                          else
                          {
                            v328 = v335;
                            v203 = -297893534;
                          }
                        }
                        if ( v203 <= 1095165696 )
                          break;
                        if ( v203 > 1928266300 )
                        {
                          if ( v203 == 1928266301 )
                          {
                            v348 = v306;
                            sub_56E5AFC(v306);
                            v204 = v344;
                            v333 = v336;
                            v203 = -1977634016;
                            i3 = 2605311197LL;
                            if ( !*((_QWORD *)v336 + 1) )
                              v203 = -1689656099;
                          }
                          else
                          {
                            v203 = -413123324;
                            i3 = 2605311197LL;
                            if ( v343 )
                              v203 = -1689656099;
                          }
                        }
                        else if ( v203 == 1095165697 )
                        {
                          v203 = -575301484;
                        }
                        else
                        {
                          v205 = v303;
                          v545 = v309;
                          v46 = v303 - *v309;
                          *(_QWORD *)&nptr[0] = v46;
                          v206 = *((_QWORD *)v204 + 30);
                          for ( i29 = 563187957; ; i29 = -1643462965 )
                          {
                            while ( i29 > 134251944 )
                            {
                              if ( i29 == 134251945 )
                              {
                                i29 = -1991102596;
                                if ( (_BYTE)v485 )
                                  i29 = 1392767983;
                              }
                              else if ( i29 == 1392767983 )
                              {
                                i29 = -1643462965;
                                v46 = 0;
                              }
                              else
                              {
                                LOBYTE(v485) = *(_QWORD *)&nptr[0] < v206;
                                i29 = 134251945;
                              }
                            }
                            if ( i29 != -1991102596 )
                              break;
                            v46 = (__int64)v545;
                            *(_QWORD *)v545 = v205;
                            LOBYTE(v46) = 1;
                          }
                          v203 = -839058132;
                          i3 = 4271504012LL;
                          if ( (v46 & 1) != 0 )
                            v203 = -23463284;
                        }
                      }
                      if ( v203 != -297893534 )
                        break;
                      v266 = v335;
                      *v335 = 1;
                      v266[1] = 47;
                      v266[2] = 89;
                      v266[3] = 7;
                      v266[4] = 27;
                      v266[5] = 28;
                      v266[6] = 6;
                      v266[7] = 94;
                      v266[8] = 20;
                      v266[9] = 26;
                      v266[10] = 8;
                      v266[11] = 18;
                      v266[12] = 12;
                      v266[13] = 8;
                      v266[14] = 85;
                      v266[15] = 21;
                      v266[16] = 17;
                      v266[17] = 9;
                      v266[18] = 19;
                      v266[19] = 29;
                      LOBYTE(v3) = 75;
                      v266[20] = 75;
                      v266[21] = 27;
                      v266[22] = 84;
                      v266[23] = 85;
                      v266[24] = 79;
                      v266[25] = 31;
                      v266[26] = 2;
                      v266[27] = 12;
                      v266[28] = 24;
                      v266[29] = 13;
                      v266[30] = 5;
                      v266[31] = 27;
                      v266[32] = 5;
                      v266[33] = 36;
                      v266[34] = 121;
                      v266[35] = 25;
                      v266[36] = 61;
                      v266[37] = 61;
                      v266[38] = 39;
                      v266[39] = 41;
                      v266[40] = 127;
                      qmemcpy(v266 + 41, "=+40?uwvhhkkmln$*8$/.>&#RX", 26);
                      v266[67] = 26;
                      v266[68] = 93;
                      v266[69] = 93;
                      v266[70] = 81;
                      v266[71] = 93;
                      v266[72] = 69;
                      v266[73] = 91;
                      v266[74] = 91;
                      v266[75] = 18;
                      qmemcpy(v266 + 76, "X^LP[ByQKHGO", 12);
                      LOBYTE(v46) = 79;
                      v266[88] = 14;
                      v266[89] = 71;
                      v267 = v266 + 90;
                      *(_QWORD *)&nptr[0] = v266 + 92;
                      v268 = 434048087;
                      while ( v268 != -1401140967 )
                      {
                        *v267++ = 0;
                        v268 = 434048087;
                        v46 = 2893826329LL;
                        if ( v267 == *(_BYTE **)&nptr[0] )
                          v268 = -1401140967;
                      }
                      v269 = v335;
                      v485 = (unsigned __int64)v335;
                      LOBYTE(v349) = *v335;
                      for ( i3 = 3618971350LL; ; i3 = 740258254 )
                      {
                        while ( 1 )
                        {
                          while ( (int)i3 > 673470317 )
                          {
                            if ( (int)i3 > 810545848 )
                            {
                              if ( (_DWORD)i3 == 810545849 )
                              {
                                ++v612;
                              }
                              else
                              {
                                v545 = &v612;
                                v612 = 0;
                              }
                              i3 = 3799215558LL;
                            }
                            else if ( (_DWORD)i3 == 673470318 )
                            {
                              v46 = 0;
                              v269[90] = 0;
                              v269[91] = 0;
                              *(_BYTE *)v485 = 0;
                              i3 = 3336305662LL;
                            }
                            else
                            {
                              v46 = *(_QWORD *)&nptr[0];
                              **(_BYTE **)&nptr[0] = v354;
                              i3 = 810545849;
                            }
                          }
                          if ( (int)i3 <= -675995947 )
                            break;
                          if ( (_DWORD)i3 == -675995946 )
                          {
                            i3 = 1310473308;
                            if ( (v349 & 1) == 0 )
                              i3 = 3336305662LL;
                          }
                          else
                          {
                            i3 = 673470318;
                            if ( v612 < 0x58 )
                              i3 = 2282005025LL;
                          }
                        }
                        if ( (_DWORD)i3 != -2012962271 )
                          break;
                        v46 = v612;
                        LOBYTE(v354) = v269[1] ^ v269[v612 + 2] ^ (v612 + 1) ^ 0x58;
                        *(_QWORD *)&nptr[0] = &v269[v612 + 2];
                      }
                      v304 = v269 + 2;
                      v327 = v334;
                      v203 = -1672859852;
                    }
                    if ( v203 != -104960323 )
                      break;
                    v270 = time(0);
                    v204 = v344;
                    v303 = v270;
                    v203 = 1769080040;
                  }
                  v315 = v620;
                  v326 = v204;
                  v208 = -1247314067;
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
LABEL_1658:
                        while ( v208 > -230113715 )
                        {
                          if ( v208 <= 1352552604 )
                          {
                            if ( v208 == -230113714 )
                            {
                              std::_Rb_tree<int const,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int const>,std::allocator<std::pair<int const,std::string>>>::_M_erase(
                                &v354,
                                v356,
                                v46,
                                i3,
                                2282005025LL,
                                v592);
                            }
                            else
                            {
                              if ( v208 != 680291346 )
                              {
                                v209 = (__int64 (__fastcall **)())v344;
                                v322 = &v532;
                                sub_570482E(&v349, &v354, v46, i3, 2282005025LL, v592);
                                v314 = v620;
                                v214 = 985969181;
                                while ( 1 )
                                {
                                  while ( 1 )
                                  {
                                    while ( v214 > -657443510 )
                                    {
                                      if ( v214 <= 983097492 )
                                      {
                                        if ( v214 == -657443509 )
                                        {
                                          v214 = -2111804588;
                                          v211 = 1206600332;
                                          if ( (char *)v361 == &v350 )
                                            v214 = 1206600332;
                                        }
                                        else if ( v214 == 924154336 )
                                        {
                                          v360 = sub_57041F8(v316, v336, v210, v211, v212, v213);
                                          v211 = (__int64)(v316 + 2);
                                          v342 = v360 != (_QWORD)(v316 + 2);
                                          v214 = -1990518946;
                                        }
                                        else
                                        {
                                          v609 = &v611;
                                          std::string::_M_construct<char *>(
                                            &v609,
                                            *(_QWORD *)(v313 + 8),
                                            *(_QWORD *)(v313 + 8) + *(_QWORD *)(v313 + 16));
                                          v209 = &off_7CA2800;
                                          v613.m256i_i32[0] = v332;
                                          v613.m256i_i64[1] = (__int64)&v613.m256i_i64[3];
                                          std::string::_M_construct<char *>(
                                            &v613.m256i_u64[1],
                                            v609,
                                            (char *)v609 + v610);
                                          sub_5704264(v298, &v612);
                                          v612 = (unsigned __int64)&off_7CA2800;
                                          if ( (unsigned __int64 *)v613.m256i_i64[1] != &v613.m256i_u64[3] )
                                            operator delete((void *)v613.m256i_i64[1]);
                                          if ( v609 != &v611 )
                                            operator delete(v609);
                                          v361 = std::_Rb_tree_increment(v361);
                                          v214 = -1386401952;
                                        }
                                      }
                                      else if ( v214 <= 1188221911 )
                                      {
                                        if ( v214 != 985969181 )
                                        {
                                          std::_Rb_tree<int const,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int const>,std::allocator<std::pair<int const,std::string>>>::_M_erase(
                                            &v349,
                                            v351,
                                            v210,
                                            v211,
                                            v212,
                                            v213);
                                          v321 = &v485;
                                          v485 = 0x5E061C1B07592F01LL;
                                          v486 = 20;
                                          v487 = 26;
                                          v488 = 8;
                                          v489 = 18;
                                          v490 = 12;
                                          v491 = 8;
                                          v492 = 85;
                                          v493 = 21;
                                          v494 = 17;
                                          v495 = 9;
                                          v496 = 19;
                                          v497 = 29;
                                          v498 = 75;
                                          v499 = 27;
                                          v500 = 84;
                                          v501 = 85;
                                          v502 = 79;
                                          v503 = 31;
                                          v504 = 2;
                                          v505 = 12;
                                          v506 = 24;
                                          v507 = 13;
                                          v508 = 5;
                                          v509 = 27;
                                          v510 = 5;
                                          v511 = 36;
                                          v512 = 121;
                                          v513 = 25;
                                          qmemcpy(v514, "==')", sizeof(v514));
                                          v515 = 127;
                                          qmemcpy(v516, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v516));
                                          v517 = 26;
                                          v518 = 93;
                                          v519 = 93;
                                          v520 = 81;
                                          v521 = 93;
                                          v522 = 69;
                                          v523 = 91;
                                          v524 = 91;
                                          v525 = 18;
                                          qmemcpy(v526, "X^LP[ByQKHGO", sizeof(v526));
                                          v527 = 14;
                                          v528 = 71;
                                          *(_QWORD *)&nptr[0] = v531;
                                          v227 = 434048087;
                                          v228 = &v529;
                                          v204 = v344;
                                          v46 = (__int64)&v485 + 2;
                                          while ( v227 != -1401140967 )
                                          {
                                            *v228++ = 0;
                                            v227 = 434048087;
                                            if ( v228 == *(char **)&nptr[0] )
                                              v227 = -1401140967;
                                          }
                                          v616 = &v485;
                                          LOBYTE(v594) = v485;
                                          for ( i30 = -675995946; ; i30 = 740258254 )
                                          {
                                            while ( 1 )
                                            {
                                              while ( i30 > 673470317 )
                                              {
                                                if ( i30 > 810545848 )
                                                {
                                                  if ( i30 == 810545849 )
                                                  {
                                                    v609 = (char *)v609 + 1;
                                                  }
                                                  else
                                                  {
                                                    v612 = (unsigned __int64)&v609;
                                                    v609 = 0;
                                                  }
                                                  i30 = -495751738;
                                                }
                                                else if ( i30 == 673470318 )
                                                {
                                                  v529 = 0;
                                                  v530 = 0;
                                                  *(_BYTE *)v616 = 0;
                                                  i30 = -958661634;
                                                }
                                                else
                                                {
                                                  **(_BYTE **)&nptr[0] = v592[0];
                                                  i30 = 810545849;
                                                }
                                              }
                                              if ( i30 <= -675995947 )
                                                break;
                                              if ( i30 == -675995946 )
                                              {
                                                i30 = 1310473308;
                                                if ( (v594 & 1) == 0 )
                                                  i30 = -958661634;
                                              }
                                              else
                                              {
                                                i30 = 673470318;
                                                if ( (unsigned __int64)v609 < 0x58 )
                                                  i30 = -2012962271;
                                              }
                                            }
                                            if ( i30 != -2012962271 )
                                              break;
                                            LOBYTE(v592[0]) = BYTE1(v485)
                                                            ^ *((_BYTE *)v609 + (_QWORD)&v485 + 2)
                                                            ^ ((_BYTE)v609 + 1)
                                                            ^ 0x58;
                                            *(_QWORD *)&nptr[0] = (char *)v609 + (_QWORD)&v485 + 2;
                                          }
                                          v300 = (char *)&v485 + 2;
                                          v320 = &v473;
                                          v473 = 0x5C1D57585B492F01LL;
                                          LOBYTE(v46) = 91;
                                          v474 = 74;
                                          v475 = 86;
                                          v476 = 87;
                                          v477 = 18;
                                          qmemcpy(v478, "AQFC[\\\tFNB", sizeof(v478));
                                          v479 = 23;
                                          v480 = 11;
                                          v481 = 75;
                                          *(_QWORD *)&nptr[0] = v484;
                                          i3 = 3160756352LL;
                                          v236 = &v482;
                                          while ( (_DWORD)i3 != -919254716 )
                                          {
                                            *v236++ = 0;
                                            i3 = 3160756352LL;
                                            v46 = 3375712580LL;
                                            if ( v236 == *(char **)&nptr[0] )
                                              i3 = 3375712580LL;
                                          }
                                          v609 = &v473;
                                          LOBYTE(v345) = v473;
                                          for ( i31 = 185907318; ; i31 = 1982752890 )
                                          {
                                            while ( 1 )
                                            {
                                              while ( i31 > 886249242 )
                                              {
                                                if ( i31 > 1108581097 )
                                                {
                                                  if ( i31 == 1108581098 )
                                                  {
                                                    i31 = 886249243;
                                                    i3 = 174559871;
                                                    if ( v592[0] < (char *)&dword_14 + 3 )
                                                      i31 = 174559871;
                                                  }
                                                  else
                                                  {
                                                    i3 = v612;
                                                    LOBYTE(v46) = v367;
                                                    *((_BYTE *)v592[0]++ + v612) = v367;
                                                    i31 = 1108581098;
                                                  }
                                                }
                                                else if ( i31 == 886249243 )
                                                {
                                                  i3 = 0;
                                                  v482 = 0;
                                                  v483 = 0;
                                                  *(_BYTE *)v609 = 0;
                                                  i31 = 862340680;
                                                }
                                                else
                                                {
                                                  v616 = v592;
                                                  v592[0] = 0;
                                                  i31 = 1108581098;
                                                }
                                              }
                                              if ( i31 > 366432057 )
                                                break;
                                              if ( i31 == 174559871 )
                                              {
                                                LODWORD(v594) = v592[0];
                                                v612 = (unsigned __int64)&v473 + 2;
                                                *(void **)&nptr[0] = v592[0];
                                                i31 = 366432058;
                                              }
                                              else
                                              {
                                                i31 = 920627274;
                                                if ( (v345 & 1) == 0 )
                                                  i31 = 862340680;
                                              }
                                            }
                                            if ( i31 != 366432058 )
                                              break;
                                            i3 = (unsigned int)v594;
                                            LOBYTE(i3) = v594 + 1;
                                            LOBYTE(v367) = (v594 + 1)
                                                         ^ BYTE1(v473)
                                                         ^ *(_BYTE *)(v612 + *(_QWORD *)&nptr[0])
                                                         ^ 0x17;
                                          }
                                          v299 = (char *)&v473 + 2;
                                          v208 = -1936494864;
                                          goto LABEL_1658;
                                        }
                                        v214 = 1188221912;
                                        v211 = 2949622140LL;
                                        if ( !v353 )
                                          v214 = -1345345156;
                                      }
                                      else if ( v214 == 1188221912 )
                                      {
                                        v319 = &v361;
                                        v361 = v352;
                                        v318 = nptr;
                                        *(_QWORD *)&nptr[0] = &off_7CA2848;
                                        v211 = 0;
                                        memset((char *)nptr + 8, 0, 24);
                                        v450 = v452;
                                        v451 = 0;
                                        v452[0] = 0;
                                        v317 = &v360;
                                        v316 = v312;
                                        v214 = 924154336;
                                      }
                                      else
                                      {
                                        v330 = v620;
                                        for ( LODWORD(v215) = -1405111860; ; LODWORD(v215) = 139007939 )
                                        {
                                          while ( 1 )
                                          {
                                            while ( (int)v215 > 566702138 )
                                            {
                                              if ( (_DWORD)v215 == 566702139 )
                                              {
                                                v345 = v451;
                                                v216 = 15683199;
                                                while ( v216 != -1747789055 )
                                                {
                                                  if ( v216 == -905888113 )
                                                  {
                                                    for ( i32 = 693113538; ; i32 = -170651053 )
                                                    {
                                                      while ( 1 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( i32 > 693113537 )
                                                          {
                                                            if ( i32 > 1563511586 )
                                                            {
                                                              if ( i32 == 1563511587 )
                                                              {
                                                                LOBYTE(v215) = v366 | 0x80;
                                                                i32 = -475423977;
                                                              }
                                                              else
                                                              {
                                                                i32 = 1072704708;
                                                                if ( !v367 )
                                                                  i32 = -1340685559;
                                                              }
                                                            }
                                                            else if ( i32 == 693113538 )
                                                            {
                                                              i32 = -1752948638;
                                                              v209 = (__int64 (__fastcall **)())&word_12;
                                                            }
                                                            else
                                                            {
                                                              v592[0] = *(void **)v594;
                                                              i32 = -1331101447;
                                                            }
                                                          }
                                                          if ( i32 <= -475423978 )
                                                            break;
                                                          if ( i32 == -475423977 )
                                                          {
                                                            v367 = (unsigned __int64)v616 >> 7;
                                                            v594 = (__int64)&v362;
                                                            sub_56E41BA(v362, (unsigned int)(char)v215);
                                                            i32 = 1696537547;
                                                            if ( v367 > 0x7F )
                                                              i32 = -1752948638;
                                                            v209 = (__int64 (__fastcall **)())v367;
                                                          }
                                                          else
                                                          {
                                                            i32 = -1340685559;
                                                          }
                                                        }
                                                        if ( i32 != -1752948638 )
                                                          break;
                                                        v616 = v209;
                                                        LOBYTE(v366) = (_BYTE)v209;
                                                        i32 = -475423977;
                                                        if ( (unsigned __int64)v209 >= 0x81 )
                                                          i32 = 1563511587;
                                                        LOBYTE(v215) = v366;
                                                      }
                                                      if ( i32 != -1331101447 )
                                                        break;
                                                      sub_56E41BA(v592[0], (unsigned int)(char)v367);
                                                    }
                                                    v209 = (__int64 (__fastcall **)())v451;
                                                    v218 = -1752948638;
                                                    if ( !v451 )
                                                      v218 = -1340685559;
                                                    for ( i33 = 693113538; ; i33 = -170651053 )
                                                    {
                                                      while ( 1 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            v220 = i33;
                                                            v215 = v210;
                                                            if ( i33 <= 693113537 )
                                                              break;
                                                            if ( i33 > 1563511586 )
                                                            {
                                                              if ( i33 == 1563511587 )
                                                              {
                                                                LOBYTE(v3) = v366 | 0x80;
                                                                i33 = -475423977;
                                                              }
                                                              else
                                                              {
                                                                i33 = 1072704708;
                                                                if ( !v367 )
                                                                  i33 = -1340685559;
                                                              }
                                                            }
                                                            else
                                                            {
                                                              v210 = v209;
                                                              i33 = v218;
                                                              if ( v220 != 693113538 )
                                                              {
                                                                v210 = v215;
                                                                i33 = v220;
                                                                if ( v220 == 1072704708 )
                                                                {
                                                                  v592[0] = *(void **)v594;
                                                                  i33 = -1331101447;
                                                                  v210 = v215;
                                                                }
                                                              }
                                                            }
                                                          }
                                                          if ( i33 <= -475423978 )
                                                            break;
                                                          if ( i33 == -475423977 )
                                                          {
                                                            v367 = (unsigned __int64)v616 >> 7;
                                                            v594 = (__int64)&v362;
                                                            sub_56E41BA(v362, (unsigned int)(char)v3);
                                                            i33 = 1696537547;
                                                            if ( v367 > 0x7F )
                                                              i33 = -1752948638;
                                                            v210 = (void *)v367;
                                                          }
                                                          else
                                                          {
                                                            i33 = -1340685559;
                                                          }
                                                        }
                                                        if ( i33 != -1752948638 )
                                                          break;
                                                        v616 = v210;
                                                        LOBYTE(v366) = (_BYTE)v210;
                                                        i33 = -475423977;
                                                        if ( (unsigned __int64)v210 >= 0x81 )
                                                          i33 = 1563511587;
                                                        LOBYTE(v3) = v366;
                                                      }
                                                      if ( i33 != -1331101447 )
                                                        break;
                                                      sub_56E41BA(v592[0], (unsigned int)(char)v367);
                                                      v210 = v215;
                                                    }
                                                    std::string::_M_append(v362, v450, v451);
                                                    v216 = -1747789055;
                                                  }
                                                  else
                                                  {
                                                    v216 = -905888113;
                                                    if ( !v345 )
                                                      v216 = -1747789055;
                                                  }
                                                }
                                                LODWORD(v215) = -1619953202;
                                              }
                                              else if ( (_DWORD)v215 == 735536065 )
                                              {
                                                (**(void (__fastcall ***)(void **))mutex->__align)(&v616);
                                                v366 = (unsigned __int64)v617;
                                                v221 = 15683199;
                                                while ( v221 != -1747789055 )
                                                {
                                                  if ( v221 == -905888113 )
                                                  {
                                                    for ( i34 = 693113538; ; i34 = -170651053 )
                                                    {
                                                      while ( 1 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( i34 > 693113537 )
                                                          {
                                                            if ( i34 > 1563511586 )
                                                            {
                                                              if ( i34 == 1563511587 )
                                                              {
                                                                LOBYTE(v215) = v346 | 0x80;
                                                                i34 = -475423977;
                                                              }
                                                              else
                                                              {
                                                                i34 = 1072704708;
                                                                if ( !v345 )
                                                                  i34 = -1340685559;
                                                              }
                                                            }
                                                            else if ( i34 == 693113538 )
                                                            {
                                                              i34 = -1752948638;
                                                              v209 = (__int64 (__fastcall **)())(byte_9 + 1);
                                                            }
                                                            else
                                                            {
                                                              v594 = *(_QWORD *)v367;
                                                              i34 = -1331101447;
                                                            }
                                                          }
                                                          if ( i34 <= -475423978 )
                                                            break;
                                                          if ( i34 == -475423977 )
                                                          {
                                                            v345 = (unsigned __int64)v592[0] >> 7;
                                                            v367 = (unsigned __int64)&v362;
                                                            sub_56E41BA(v362, (unsigned int)(char)v215);
                                                            i34 = 1696537547;
                                                            if ( v345 > 0x7F )
                                                              i34 = -1752948638;
                                                            v209 = (__int64 (__fastcall **)())v345;
                                                          }
                                                          else
                                                          {
                                                            i34 = -1340685559;
                                                          }
                                                        }
                                                        if ( i34 != -1752948638 )
                                                          break;
                                                        v592[0] = v209;
                                                        v346 = (char)v209;
                                                        i34 = -475423977;
                                                        if ( (unsigned __int64)v209 >= 0x81 )
                                                          i34 = 1563511587;
                                                        LOBYTE(v215) = v346;
                                                      }
                                                      if ( i34 != -1331101447 )
                                                        break;
                                                      sub_56E41BA(v594, (unsigned int)(char)v345);
                                                    }
                                                    v209 = v617;
                                                    v223 = -1752948638;
                                                    if ( !v617 )
                                                      v223 = -1340685559;
                                                    for ( i35 = 693113538; ; i35 = -170651053 )
                                                    {
                                                      while ( 1 )
                                                      {
                                                        while ( 1 )
                                                        {
                                                          while ( 1 )
                                                          {
                                                            v225 = i35;
                                                            v215 = v210;
                                                            if ( i35 <= 693113537 )
                                                              break;
                                                            if ( i35 > 1563511586 )
                                                            {
                                                              if ( i35 == 1563511587 )
                                                              {
                                                                LOBYTE(v3) = v346 | 0x80;
                                                                i35 = -475423977;
                                                              }
                                                              else
                                                              {
                                                                i35 = 1072704708;
                                                                if ( !v345 )
                                                                  i35 = -1340685559;
                                                              }
                                                            }
                                                            else
                                                            {
                                                              v210 = v209;
                                                              i35 = v223;
                                                              if ( v225 != 693113538 )
                                                              {
                                                                v210 = v215;
                                                                i35 = v225;
                                                                if ( v225 == 1072704708 )
                                                                {
                                                                  v594 = *(_QWORD *)v367;
                                                                  i35 = -1331101447;
                                                                  v210 = v215;
                                                                }
                                                              }
                                                            }
                                                          }
                                                          if ( i35 <= -475423978 )
                                                            break;
                                                          if ( i35 == -475423977 )
                                                          {
                                                            v345 = (unsigned __int64)v592[0] >> 7;
                                                            v367 = (unsigned __int64)&v362;
                                                            sub_56E41BA(v362, (unsigned int)(char)v3);
                                                            i35 = 1696537547;
                                                            if ( v345 > 0x7F )
                                                              i35 = -1752948638;
                                                            v210 = (void *)v345;
                                                          }
                                                          else
                                                          {
                                                            i35 = -1340685559;
                                                          }
                                                        }
                                                        if ( i35 != -1752948638 )
                                                          break;
                                                        v592[0] = v210;
                                                        v346 = (char)v210;
                                                        i35 = -475423977;
                                                        if ( (unsigned __int64)v210 >= 0x81 )
                                                          i35 = 1563511587;
                                                        LOBYTE(v3) = v346;
                                                      }
                                                      if ( i35 != -1331101447 )
                                                        break;
                                                      sub_56E41BA(v594, (unsigned int)(char)v345);
                                                      v210 = v215;
                                                    }
                                                    std::string::_M_append(v362, v616, v617);
                                                    v221 = -1747789055;
                                                  }
                                                  else
                                                  {
                                                    v221 = -905888113;
                                                    if ( !v366 )
                                                      v221 = -1747789055;
                                                  }
                                                }
                                                if ( v616 != &v618 )
                                                  operator delete(v616);
                                                mutex->__align += 48;
                                                LODWORD(v215) = 1270937927;
                                              }
                                              else
                                              {
                                                LODWORD(v215) = 735536065;
                                                if ( mutex->__align == *v338 )
                                                  LODWORD(v215) = 566702139;
                                              }
                                            }
                                            if ( (int)v215 <= -1152980463 )
                                              break;
                                            v365 = (char *)v338;
                                            *v338 = v340[1];
                                            LODWORD(v215) = 1270937927;
                                          }
                                          if ( (_DWORD)v215 != -1405111860 )
                                            break;
                                          mutex = (pthread_mutex_t *)v620;
                                          v338 = v619;
                                          v532 = v534;
                                          v533 = 0;
                                          v534[0] = 0;
                                          p_mutex = (pthread_mutex_t **)&v362;
                                          v362 = &v532;
                                          v340 = (void **)nptr + 1;
                                          v341 = (char *)v620;
                                          v620[0] = *((_QWORD *)&nptr[0] + 1);
                                        }
                                        *(_QWORD *)&nptr[0] = &off_7CA2848;
                                        if ( v450 != v452 )
                                          operator delete(v450);
                                        sub_570480E((char *)nptr + 8);
                                        v214 = 983097493;
                                      }
                                    }
                                    if ( v214 <= -1439742577 )
                                      break;
                                    if ( v214 == -1439742576 )
                                    {
                                      std::string::_M_assign(&v450, v360 + 72);
                                      v214 = -2129447168;
                                    }
                                    else if ( v214 == -1386401952 )
                                    {
LABEL_1811:
                                      v214 = -657443509;
                                    }
                                    else
                                    {
                                      v532 = v534;
                                      v226 = sub_56F9F18(&buf);
                                      std::string::_M_construct<char const*>(&v532, &buf, &buf + v226);
                                      v214 = 983097493;
                                    }
                                  }
                                  if ( v214 == -2129447168 )
                                    goto LABEL_1811;
                                  if ( v214 == -2111804588 )
                                  {
                                    v298 = (char *)nptr + 8;
                                    v331 = &v612;
                                    v211 = *(unsigned int *)(v361 + 32);
                                    v332 = *(_DWORD *)(v361 + 32);
                                    v313 = v361 + 32;
                                    v214 = 942904285;
                                  }
                                  else
                                  {
                                    v214 = -2129447168;
                                    v211 = 2855224720LL;
                                    if ( v342 )
                                      v214 = -1439742576;
                                  }
                                }
                              }
                              sub_56A4A43(v302, 237, v301, "[FGESDK]", 2);
                            }
                            v208 = -569942109;
                            goto LABEL_2084;
                          }
                          if ( v208 == 1352552605 )
                          {
                            v325 = &v545;
                            v545 = (void *)0x5E061C1B07592F01LL;
                            v546 = 20;
                            v547 = 26;
                            v548 = 8;
                            v549 = 18;
                            v550 = 12;
                            v551 = 8;
                            v552 = 85;
                            v553 = 21;
                            v554 = 17;
                            v555 = 9;
                            v556 = 19;
                            v557 = 29;
                            v558 = 75;
                            v559 = 27;
                            v560 = 84;
                            v561 = 85;
                            v562 = 79;
                            v563 = 31;
                            v564 = 2;
                            v565 = 12;
                            v566 = 24;
                            v567 = 13;
                            v568 = 5;
                            v569 = 27;
                            v570 = 5;
                            v571 = 36;
                            LOBYTE(v46) = 121;
                            v572 = 121;
                            v573 = 25;
                            qmemcpy(v574, "==')", sizeof(v574));
                            v575 = 127;
                            qmemcpy(v576, "=+40?uwvhhkkmln$*8$/.>&#RX", sizeof(v576));
                            v577 = 26;
                            v578 = 93;
                            v579 = 93;
                            LOBYTE(v3) = 81;
                            v580 = 81;
                            v581 = 93;
                            v582 = 69;
                            v583 = 91;
                            v584 = 91;
                            v585 = 18;
                            qmemcpy(v586, "X^LP[ByQKHGO", sizeof(v586));
                            v587 = 14;
                            v588 = 71;
                            *(_QWORD *)&nptr[0] = v591;
                            i3 = 434048087;
                            v234 = &v589;
                            while ( (_DWORD)i3 != -1401140967 )
                            {
                              *v234++ = 0;
                              i3 = 434048087;
                              v46 = 2893826329LL;
                              if ( v234 == *(char **)&nptr[0] )
                                i3 = 2893826329LL;
                            }
                            v208 = 1498882788;
                          }
                          else
                          {
                            if ( v208 != 1498882788 )
                            {
                              *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
                              *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
                              *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
                              *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
                              v450 = (void *)0x29273D3D19792405LL;
                              v451 = 0x77753F30342B3D7FLL;
                              qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
                              v453 = (void *)0x5D515D5D1A585223LL;
                              v454 = 69;
                              v455 = 91;
                              v456 = 91;
                              v457 = 18;
                              qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
                              v459 = 14;
                              v460 = 71;
                              v612 = (unsigned __int64)v463;
                              v230 = 434048087;
                              v231 = &v461;
                              while ( v230 != -1401140967 )
                              {
                                *v231++ = 0;
                                v230 = 434048087;
                                if ( v231 == (char *)v612 )
                                  v230 = -1401140967;
                              }
                              v609 = nptr;
                              LOBYTE(v367) = nptr[0];
                              for ( i36 = -675995946; ; i36 = 740258254 )
                              {
                                while ( 1 )
                                {
                                  while ( i36 > 673470317 )
                                  {
                                    if ( i36 > 810545848 )
                                    {
                                      if ( i36 == 810545849 )
                                      {
                                        ++v592[0];
                                      }
                                      else
                                      {
                                        v616 = v592;
                                        v592[0] = 0;
                                      }
                                      i36 = -495751738;
                                    }
                                    else if ( i36 == 673470318 )
                                    {
                                      v461 = 0;
                                      v462 = 0;
                                      *(_BYTE *)v609 = 0;
                                      i36 = -958661634;
                                    }
                                    else
                                    {
                                      *(_BYTE *)v612 = v594;
                                      i36 = 810545849;
                                    }
                                  }
                                  if ( i36 <= -675995947 )
                                    break;
                                  if ( i36 == -675995946 )
                                  {
                                    i36 = 1310473308;
                                    if ( (v367 & 1) == 0 )
                                      i36 = -958661634;
                                  }
                                  else
                                  {
                                    i36 = 673470318;
                                    if ( v592[0] < &qword_58 )
                                      i36 = -2012962271;
                                  }
                                }
                                if ( i36 != -2012962271 )
                                  break;
                                LOBYTE(v594) = BYTE1(nptr[0])
                                             ^ *((_BYTE *)nptr + (unsigned __int64)v592[0] + 2)
                                             ^ (LOBYTE(v592[0]) + 1)
                                             ^ 0x58;
                                v612 = (unsigned __int64)nptr + (unsigned __int64)v592[0] + 2;
                              }
                              v612 = 0x697B6F6C7A682F01LL;
                              qmemcpy(&v613, "-ffvheb$lt}w9x~uqww11dr`VEOM", 28);
                              v613.m256i_i16[14] = 2835;
                              v613.m256i_i8[30] = 75;
                              v616 = v615;
                              v238 = 1432350809;
                              v239 = &v613.m256i_i8[31];
                              while ( v238 != 1897238988 )
                              {
                                *v239++ = 0;
                                v238 = 1432350809;
                                if ( v239 == v616 )
                                  v238 = 1897238988;
                              }
                              v594 = (__int64)&v612;
                              LOBYTE(v366) = v612;
                              for ( i37 = -1468158444; ; i37 = -537877447 )
                              {
                                while ( 1 )
                                {
                                  while ( i37 <= 678513966 )
                                  {
                                    if ( i37 > -537877448 )
                                    {
                                      if ( i37 == -537877447 )
                                      {
                                        i37 = 1181823369;
                                        if ( v367 < 0x25 )
                                          i37 = 897346759;
                                      }
                                      else
                                      {
                                        *((_BYTE *)v616 + v367++) = v345;
                                        i37 = -537877447;
                                      }
                                    }
                                    else if ( i37 == -2139562399 )
                                    {
                                      v616 = (char *)&v612 + 2;
                                      LOBYTE(v345) = BYTE1(v612)
                                                   ^ *((_BYTE *)&v612 + v367 + 2)
                                                   ^ ((-2 - (_BYTE)v609) & 0xC6 | ((_BYTE)v609 + 1) & 0x39)
                                                   ^ 0xE3;
                                      i37 = -416917990;
                                    }
                                    else
                                    {
                                      i37 = 883426621;
                                      if ( (v366 & 1) == 0 )
                                        i37 = 678513967;
                                    }
                                  }
                                  if ( i37 <= 897346758 )
                                    break;
                                  if ( i37 == 897346759 )
                                  {
                                    v609 = (void *)v367;
                                    i37 = -2139562399;
                                  }
                                  else
                                  {
                                    v613.m256i_i8[31] = 0;
                                    v614 = 0;
                                    *(_BYTE *)v594 = 0;
                                    i37 = 678513967;
                                  }
                                }
                                if ( i37 != 883426621 )
                                  break;
                                v592[0] = &v367;
                                v367 = 0;
                              }
                              sub_56A4A43((char *)nptr + 2, 249, (char *)&v612 + 2, "[FGESDK]", 2);
                              goto LABEL_2083;
                            }
                            v616 = &v545;
                            LOBYTE(v594) = (_BYTE)v545;
                            for ( i38 = -675995946; ; i38 = 740258254 )
                            {
                              while ( 1 )
                              {
                                while ( i38 > 673470317 )
                                {
                                  if ( i38 > 810545848 )
                                  {
                                    if ( i38 == 810545849 )
                                    {
                                      v609 = (char *)v609 + 1;
                                    }
                                    else
                                    {
                                      v612 = (unsigned __int64)&v609;
                                      v609 = 0;
                                    }
                                    i38 = -495751738;
                                  }
                                  else if ( i38 == 673470318 )
                                  {
                                    v589 = 0;
                                    v590 = 0;
                                    *(_BYTE *)v616 = 0;
                                    i38 = -958661634;
                                  }
                                  else
                                  {
                                    **(_BYTE **)&nptr[0] = v592[0];
                                    i38 = 810545849;
                                  }
                                }
                                if ( i38 <= -675995947 )
                                  break;
                                if ( i38 == -675995946 )
                                {
                                  i38 = 1310473308;
                                  if ( (v594 & 1) == 0 )
                                    i38 = -958661634;
                                }
                                else
                                {
                                  i38 = 673470318;
                                  if ( (unsigned __int64)v609 < 0x58 )
                                    i38 = -2012962271;
                                }
                              }
                              if ( i38 != -2012962271 )
                                break;
                              LOBYTE(v592[0]) = BYTE1(v545)
                                              ^ *((_BYTE *)v609 + (_QWORD)&v545 + 2)
                                              ^ ((_BYTE)v609 + 1)
                                              ^ 0x58;
                              *(_QWORD *)&nptr[0] = (char *)v609 + (_QWORD)&v545 + 2;
                            }
                            v302 = (char *)&v545 + 2;
                            v324 = &v535;
                            v535 = 0x6674606375672F01LL;
                            LOBYTE(v46) = 116;
                            qmemcpy(v536, "\"iiygjm+c{rx6wqz~xx>>t\\~lLGB", sizeof(v536));
                            v537 = 6;
                            v538 = 72;
                            v539 = 83;
                            v540 = 3;
                            qmemcpy(v541, "LX@C", sizeof(v541));
                            *(_QWORD *)&nptr[0] = v544;
                            i3 = 53855480;
                            v243 = &v542;
                            while ( (_DWORD)i3 != -659242669 )
                            {
                              *v243++ = 0;
                              i3 = 53855480;
                              v46 = 3635724627LL;
                              if ( v243 == *(char **)&nptr[0] )
                                i3 = 3635724627LL;
                            }
                            v609 = &v535;
                            LOBYTE(v345) = v535;
                            for ( i39 = -1694899481; ; i39 = -197543922 )
                            {
                              while ( 1 )
                              {
                                while ( i39 > -344511993 )
                                {
                                  if ( i39 > 1285572307 )
                                  {
                                    if ( i39 == 1285572308 )
                                    {
                                      LODWORD(v594) = v592[0];
                                      v612 = (unsigned __int64)&v535 + 2;
                                      *(_QWORD *)&nptr[0] = &v536[(unsigned __int64)v592[0] - 6];
                                      i39 = -344511992;
                                    }
                                    else
                                    {
                                      i3 = 0;
                                      v542 = 0;
                                      v543 = 0;
                                      *(_BYTE *)v609 = 0;
                                      i39 = -1732185182;
                                    }
                                  }
                                  else if ( i39 == -344511992 )
                                  {
                                    LOBYTE(v367) = **(_BYTE **)&nptr[0];
                                    i39 = -1809370947;
                                  }
                                  else
                                  {
                                    i39 = 1325648788;
                                    if ( v592[0] < (char *)&qword_28 + 2 )
                                      i39 = 1285572308;
                                  }
                                }
                                if ( i39 <= -1694899482 )
                                  break;
                                if ( i39 == -1694899481 )
                                {
                                  i39 = -1687380215;
                                  if ( (v345 & 1) == 0 )
                                    i39 = -1732185182;
                                }
                                else
                                {
                                  v616 = v592;
                                  v592[0] = 0;
                                  i39 = -197543922;
                                }
                              }
                              if ( i39 != -1809370947 )
                                break;
                              LOBYTE(i3) = ((-2 - v594) & 0x92 | (v594 + 1) & 0x6D) ^ BYTE1(v535) ^ v367 ^ 0xB8;
                              v46 = v612;
                              *((_BYTE *)v592[0]++ + v612) = i3;
                            }
                            v301 = (char *)&v535 + 2;
                            v208 = 680291346;
                          }
                        }
                        if ( v208 > -1247314068 )
                          break;
                        if ( v208 == -2116383695 )
                        {
                          sub_56957EC(&v470, v532, &p_mutex);
                          v616 = &v618;
                          v232 = (unsigned __int64)v344;
                          std::string::_M_construct<char *>(
                            &v616,
                            *((_QWORD *)v344 + 8),
                            *((_QWORD *)v344 + 8) + *((_QWORD *)v344 + 9));
                          v612 = v232;
                          v613.m256i_i64[0] = (__int64)&v613.m256i_i64[2];
                          std::string::_M_construct<char *>(&v613, v616, (char *)v617 + (_QWORD)v616);
                          v233 = (char *)operator new(0x28u);
                          *(_QWORD *)v233 = v612;
                          *((_QWORD *)v233 + 1) = v233 + 24;
                          if ( (unsigned __int64 *)v613.m256i_i64[0] == &v613.m256i_u64[2] )
                          {
                            *(_OWORD *)(v233 + 24) = *(_OWORD *)&v613.m256i_u64[2];
                          }
                          else
                          {
                            *((_QWORD *)v233 + 1) = v613.m256i_i64[0];
                            *((_QWORD *)v233 + 3) = v613.m256i_i64[2];
                          }
                          *((_QWORD *)v233 + 2) = v613.m256i_i64[1];
                          v613.m256i_i64[0] = (__int64)&v613.m256i_i64[2];
                          v613.m256i_i64[1] = 0;
                          v613.m256i_i8[16] = 0;
                          v609 = v233;
                          *((_QWORD *)&v611 + 1) = sub_576A8DC;
                          *(_QWORD *)&v611 = &loc_576A8F0;
                          *(_QWORD *)&nptr[0] = 0x5E061C1B07592F01LL;
                          *((_QWORD *)&nptr[0] + 1) = 0x1555080C12081A14LL;
                          *(_QWORD *)&nptr[1] = 0x55541B4B1D130911LL;
                          *((_QWORD *)&nptr[1] + 1) = 0x1B050D180C021F4FLL;
                          v450 = (void *)0x29273D3D19792405LL;
                          v451 = 0x77753F30342B3D7FLL;
                          qmemcpy(v452, "vhhkkmln$*8$/.>&", sizeof(v452));
                          v453 = (void *)0x5D515D5D1A585223LL;
                          v454 = 69;
                          v455 = 91;
                          v456 = 91;
                          v457 = 18;
                          qmemcpy(v458, "X^LP[ByQKHGO", sizeof(v458));
                          v459 = 14;
                          v460 = 71;
                          v594 = (__int64)v463;
                          v245 = 434048087;
                          v246 = &v461;
                          while ( v245 != -1401140967 )
                          {
                            *v246++ = 0;
                            v245 = 434048087;
                            if ( v246 == (char *)v594 )
                              v245 = -1401140967;
                          }
                          v345 = (unsigned __int64)nptr;
                          LOBYTE(v341) = nptr[0];
                          for ( i40 = -675995946; ; i40 = 740258254 )
                          {
                            while ( 1 )
                            {
                              while ( i40 > 673470317 )
                              {
                                if ( i40 > 810545848 )
                                {
                                  if ( i40 == 810545849 )
                                  {
                                    ++v366;
                                  }
                                  else
                                  {
                                    v367 = (unsigned __int64)&v366;
                                    v366 = 0;
                                  }
                                  i40 = -495751738;
                                }
                                else if ( i40 == 673470318 )
                                {
                                  v461 = 0;
                                  v462 = 0;
                                  *(_BYTE *)v345 = 0;
                                  i40 = -958661634;
                                }
                                else
                                {
                                  *(_BYTE *)v594 = (_BYTE)v365;
                                  i40 = 810545849;
                                }
                              }
                              if ( i40 <= -675995947 )
                                break;
                              if ( i40 == -675995946 )
                              {
                                i40 = 1310473308;
                                if ( ((unsigned __int8)v341 & 1) == 0 )
                                  i40 = -958661634;
                              }
                              else
                              {
                                i40 = 673470318;
                                if ( v366 < 0x58 )
                                  i40 = -2012962271;
                              }
                            }
                            if ( i40 != -2012962271 )
                              break;
                            LOBYTE(v365) = BYTE1(nptr[0]) ^ *((_BYTE *)nptr + v366 + 2) ^ (v366 + 1) ^ 0x58;
                            v594 = (__int64)nptr + v366 + 2;
                          }
                          v594 = 0x125F595053572F01LL;
                          qmemcpy(v595, "@YSZR]JIZC@", sizeof(v595));
                          v596 = 6;
                          v597 = 29;
                          v598 = 0;
                          v599 = 77;
                          v600 = 71;
                          v601 = 77;
                          v602 = 12;
                          v603 = 23;
                          v604 = 11;
                          v605 = 75;
                          v367 = (unsigned __int64)&v608;
                          v248 = -769038311;
                          v249 = &v606;
                          while ( v248 != 1284930719 )
                          {
                            *v249++ = 0;
                            v248 = -769038311;
                            if ( v249 == (char *)v367 )
                              v248 = 1284930719;
                          }
                          v366 = (unsigned __int64)&v594;
                          LOBYTE(v340) = v594;
                          LODWORD(v250) = -962714612;
                          do
                          {
                            while ( 1 )
                            {
                              while ( 1 )
                              {
                                while ( (int)v250 > -324670996 )
                                {
                                  if ( (int)v250 > 307205468 )
                                  {
                                    if ( (_DWORD)v250 == 307205469 )
                                    {
                                      LODWORD(v341) = (_DWORD)v365;
                                      LODWORD(v250) = -324670995;
                                    }
                                    else if ( (_DWORD)v250 == 834103254 )
                                    {
                                      v606 = 0;
                                      v607 = 0;
                                      *(_BYTE *)v366 = 0;
                                      LODWORD(v250) = -1997885474;
                                    }
                                  }
                                  else if ( (_DWORD)v250 == -324670995 )
                                  {
                                    v365[(_QWORD)&v594 + 2] ^= ((_BYTE)v341 + 1) ^ BYTE1(v594) ^ 0x1B;
                                    v367 = (unsigned __int64)(v365 + 1);
                                    v250 = byte_28E9C53;
                                  }
                                  else if ( (_DWORD)v250 == (_DWORD)byte_28E9C53 )
                                  {
                                    v365 = (char *)v367;
                                    LODWORD(v250) = -794593716;
                                  }
                                }
                                if ( (int)v250 <= -962714613 )
                                  break;
                                if ( (_DWORD)v250 == -962714612 )
                                {
                                  LODWORD(v250) = -2083131433;
                                  if ( ((unsigned __int8)v340 & 1) == 0 )
                                    LODWORD(v250) = -1997885474;
                                }
                                else if ( (_DWORD)v250 == -794593716 )
                                {
                                  LODWORD(v250) = 834103254;
                                  if ( (unsigned __int64)v365 < 0x1B )
                                    LODWORD(v250) = 307205469;
                                }
                              }
                              if ( (_DWORD)v250 != -2083131433 )
                                break;
                              v345 = (unsigned __int64)&v365;
                              v365 = 0;
                              LODWORD(v250) = -794593716;
                            }
                          }
                          while ( (_DWORD)v250 != -1997885474 );
                          sub_56A4A43((char *)nptr + 2, 260, (char *)&v594 + 2, "[FGESDK]", 1);
                          v251 = v344;
                          v344[96] = 1;
                          v252 = sub_56956B8();
                          v253 = v251;
                          v3 = (char *)v252;
                          v345 = (unsigned __int64)v307;
                          LOBYTE(v340) = *v307;
                          v254 = 578789870;
                          v255 = v308;
                          while ( 1 )
                          {
                            while ( 1 )
                            {
                              while ( v254 > 578789869 )
                              {
                                if ( v254 > 1054713224 )
                                {
                                  if ( v254 == 1054713225 )
                                  {
                                    v254 = 933373733;
                                    if ( v366 < 8 )
                                      v254 = 1409423605;
                                  }
                                  else
                                  {
                                    LODWORD(v365) = v366;
                                    v594 = v255;
                                    v254 = -186898055;
                                  }
                                }
                                else if ( v254 == 578789870 )
                                {
                                  v254 = -2135764886;
                                  if ( ((unsigned __int8)v340 & 1) == 0 )
                                    v254 = 427872412;
                                }
                                else
                                {
                                  v253[274] = 0;
                                  v253[275] = 0;
                                  *(_BYTE *)v345 = 0;
                                  v254 = 427872412;
                                }
                              }
                              if ( v254 > 427872411 )
                                break;
                              if ( v254 == -2135764886 )
                              {
                                v367 = (unsigned __int64)&v366;
                                v366 = 0;
                                v254 = 1054713225;
                              }
                              else
                              {
                                LOBYTE(v341) = ((_BYTE)v365 + 1) ^ v253[265] ^ *(_BYTE *)(v594 + v366) ^ 8;
                                *(_QWORD *)&nptr[0] = v594 + v366;
                                v254 = 436624164;
                              }
                            }
                            if ( v254 != 436624164 )
                              break;
                            **(_BYTE **)&nptr[0] = (_BYTE)v341;
                            ++v366;
                            v254 = 1054713225;
                          }
                          v592[0] = v593;
                          v256 = v253;
                          v257 = sub_56F9F18(v255);
                          std::string::_M_construct<char const*>(v592, v255, &v256[v257 + 266]);
                          v258 = v470;
                          v259 = v471;
                          *(_QWORD *)&nptr[1] = 0;
                          if ( (_QWORD)v611 )
                          {
                            ((void (__fastcall *)(_OWORD *, void **, __int64))v611)(nptr, &v609, 2);
                            nptr[1] = v611;
                          }
                          sub_579DEA8(v3, v592, v258, v259, nptr);
                          if ( *(_QWORD *)&nptr[1] )
                            (*(void (__fastcall **)(_OWORD *, _OWORD *, __int64))&nptr[1])(nptr, nptr, 3);
                          if ( v592[0] != v593 )
                            operator delete(v592[0]);
                          if ( (_QWORD)v611 )
                            ((void (__fastcall *)(void **, void **, __int64))v611)(&v609, &v609, 3);
                          if ( v616 != &v618 )
                            operator delete(v616);
                          if ( v470 != v472 )
                            operator delete(v470);
                          if ( v532 != v534 )
                            operator delete(v532);
LABEL_2083:
                          v208 = -230113714;
LABEL_2084:
                          v204 = v344;
                          continue;
                        }
                        if ( v208 == -1936494864 )
                        {
                          sub_56A4A43(v300, 245, v299, "[FGESDK]", 1);
                          v208 = -2116383695;
                          v204 = v344;
                        }
                        else
                        {
                          v323 = &v354;
                          v355 = 0;
                          v356 = 0;
                          v357 = &v355;
                          v358 = &v355;
                          v359 = 0;
                          v229 = (*(__int64 (__fastcall **)(_QWORD, unsigned __int64 *, __int64, _QWORD, __int64, void **))(*(_QWORD *)*v326 + 16LL))(
                                   *v326,
                                   &v354,
                                   v46,
                                   0,
                                   2282005025LL,
                                   v592);
                          v204 = v344;
                          v339 = v229;
                          v43 = v229 == 0;
                          v208 = 2011745991;
                          i3 = 3986692184LL;
                          if ( v43 )
                            v208 = -308275112;
                        }
                      }
                      if ( v208 != -1247314067 )
                        break;
                      v208 = -1601390004;
                      i3 = 1352552605;
                      if ( !*v326 )
                        v208 = 1352552605;
                    }
                    if ( v208 != -308275112 )
                      break;
                    v208 = 1066960081;
                    i3 = 4064853582LL;
                    if ( !v359 )
                      v208 = -230113714;
                  }
                  v203 = -839058132;
                }
              }
              v48 = -562262634;
              if ( !v371 )
                v48 = 946759078;
            }
          }
          if ( v48 <= 1757145254 )
            break;
          if ( v48 > 2106276884 )
          {
            if ( v48 == 2106276885 )
            {
              v48 = 1757145255;
              if ( !v371 )
                v48 = 1629837579;
            }
            else
            {
              v287 = &v379;
              v379 = 0x5E061C1B07592F01LL;
              v380 = 20;
              v381 = 26;
              v382 = 8;
              v383 = 18;
              v384 = 12;
              v385 = 8;
              v386 = 85;
              v387[0] = 21;
              v387[1] = 17;
              v387[2] = 9;
              v387[3] = 19;
              v387[4] = 29;
              v387[5] = 75;
              v387[6] = 27;
              v387[7] = 84;
              v388 = 85;
              v389 = 79;
              v390[0] = 31;
              v390[1] = 2;
              v390[2] = 12;
              v390[3] = 24;
              v390[4] = 13;
              v390[5] = 5;
              v390[6] = 27;
              v390[7] = 5;
              v390[8] = 36;
              v390[9] = 121;
              v390[10] = 25;
              qmemcpy(v391, "==')", 4);
              v391[4] = 127;
              qmemcpy(v392, "=+40?uwvhhkkmln$*8$/.>&#RX", 26);
              v392[26] = 26;
              v392[27] = 93;
              v392[28] = 93;
              v392[29] = 81;
              v392[30] = 93;
              v392[31] = 69;
              LOBYTE(v46) = 91;
              v392[32] = 91;
              v392[33] = 91;
              v392[34] = 18;
              qmemcpy(v393, "X^LP[ByQKHGO", 12);
              v393[12] = 14;
              v393[13] = 71;
              *(_QWORD *)&nptr[0] = &v395;
              i3 = 434048087;
              v52 = v394;
              while ( (_DWORD)i3 != -1401140967 )
              {
                *v52++ = 0;
                i3 = 434048087;
                v46 = 2893826329LL;
                if ( v52 == *(_BYTE **)&nptr[0] )
                  i3 = 2893826329LL;
              }
              v48 = 230961172;
            }
          }
          else
          {
            if ( v48 == 1757145255 )
              goto LABEL_400;
            v48 = 911994299;
          }
        }
        if ( v48 <= 1629837578 )
          break;
        if ( v48 == 1629837579 )
        {
          v485 = (unsigned __int64)v296;
          LOBYTE(v612) = *v296;
          v63 = -2054724375;
          while ( v63 != 1928391394 )
          {
            if ( v63 == 332328591 )
            {
              *(_BYTE *)v485 = 1;
              v545 = &v554;
              v64 = sub_56F9F18("emptyToken");
              std::string::_M_construct<char const*>(&v545, "emptyToken", &aEmptytoken[v64]);
              sub_56DB6BA(nptr, &v545);
              if ( v545 != &v554 )
                operator delete(v545);
              v65 = sub_56DB816();
              sub_5B98606(v65, nptr, 1);
              if ( v468 != v294 )
                operator delete(v468);
              v49 = 1831282351;
              if ( v466 != v295 )
                operator delete(v466);
              if ( v464 != v465 )
                operator delete(v464);
              if ( v453 != &v458[4] )
                operator delete(v453);
              if ( v450 != v452 )
                operator delete(v450);
              if ( *(_OWORD **)&nptr[0] != &nptr[1] )
                operator delete(*(void **)&nptr[0]);
              v63 = 1928391394;
            }
            else
            {
              v63 = 1928391394;
              i3 = 332328591;
              if ( (v612 & 1) == 0 )
                v63 = 332328591;
            }
          }
          v48 = 1757145255;
        }
        else
        {
          if ( v397[0] != v398 )
            operator delete(v397[0]);
LABEL_400:
          v48 = 1760159394;
        }
      }
      if ( v48 != 1409059716 )
        break;
      v48 = -2007905915;
      if ( v337 )
        v48 = 607436137;
    }
    if ( v48 != 1550342641 )
      break;
    v293 = &v416;
    v416 = 1;
    v417 = 47;
    v418 = 89;
    v419 = 7;
    v420 = 27;
    v421 = 28;
    v422 = 6;
    v423 = 94;
    v424 = 20;
    v425 = 26;
    v426 = 8;
    v427 = 18;
    v428 = 12;
    v429 = 8;
    v430 = 85;
    v431 = 21;
    v432 = 17;
    v433 = 9;
    v434 = 19;
    v435 = 29;
    v436 = 75;
    v437 = 27;
    v438 = 84;
    v439 = 85;
    v440[0] = 79;
    v440[1] = 31;
    v440[2] = 2;
    v440[3] = 12;
    v440[4] = 24;
    v441 = 13;
    v442 = 5;
    v443[0] = 27;
    v443[1] = 5;
    v443[2] = 36;
    v443[3] = 121;
    v443[4] = 25;
    qmemcpy(v444, "==')", 4);
    v444[4] = 127;
    qmemcpy(v445, "=+40?uwvhhkkmln$*8$/.>&#RX", 26);
    v445[26] = 26;
    v445[27] = 93;
    v445[28] = 93;
    v445[29] = 81;
    v445[30] = 93;
    v445[31] = 69;
    v445[32] = 91;
    v445[33] = 91;
    v445[34] = 18;
    qmemcpy(v446, "X^LP[ByQKHGO", 12);
    v446[12] = 14;
    v446[13] = 71;
    *(_QWORD *)&nptr[0] = &v448;
    v50 = 434048087;
    v51 = v447;
    v46 = (__int64)&v418;
    while ( v50 != -1401140967 )
    {
      *v51++ = 0;
      v50 = 434048087;
      if ( v51 == *(_BYTE **)&nptr[0] )
        v50 = -1401140967;
    }
    v485 = (unsigned __int64)&v416;
    LOBYTE(v349) = v416;
    for ( i41 = -675995946; ; i41 = 740258254 )
    {
      while ( 1 )
      {
        while ( i41 > 673470317 )
        {
          if ( i41 > 810545848 )
          {
            if ( i41 == 810545849 )
            {
              ++v612;
            }
            else
            {
              v545 = &v612;
              v612 = 0;
            }
            i41 = -495751738;
          }
          else if ( i41 == 673470318 )
          {
            v447[0] = 0;
            v447[1] = 0;
            *(_BYTE *)v485 = 0;
            i41 = -958661634;
          }
          else
          {
            **(_BYTE **)&nptr[0] = v354;
            i41 = 810545849;
          }
        }
        if ( i41 <= -675995947 )
          break;
        if ( i41 == -675995946 )
        {
          i41 = 1310473308;
          if ( (v349 & 1) == 0 )
            i41 = -958661634;
        }
        else
        {
          i41 = 673470318;
          if ( v612 < 0x58 )
            i41 = -2012962271;
        }
      }
      if ( i41 != -2012962271 )
        break;
      LOBYTE(v354) = v417 ^ *(&v418 + v612) ^ (v612 + 1) ^ 0x58;
      *(_QWORD *)&nptr[0] = &v418 + v612;
    }
    v282 = &v418;
    v292 = &v399;
    v399 = 0x5A5D674050512F01LL;
    LOBYTE(v46) = 90;
    v400 = 85;
    v401 = 81;
    v402 = 30;
    v403 = 78;
    v404 = 75;
    v405 = 82;
    v406 = 78;
    v407 = 90;
    v408 = 80;
    v409 = 7;
    v410 = 79;
    v411 = 86;
    v412 = 4;
    qmemcpy(v413, "@NNSJ", sizeof(v413));
    *(_QWORD *)&nptr[0] = &v415;
    i3 = 4035818723LL;
    v61 = v414;
    while ( (_DWORD)i3 != -272774176 )
    {
      *v61++ = 0;
      i3 = 4035818723LL;
      v46 = 4022193120LL;
      if ( v61 == *(_BYTE **)&nptr[0] )
        i3 = 4022193120LL;
    }
    v545 = &v399;
    LOBYTE(v354) = v399;
    LODWORD(v62) = 1999295770;
    do
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( (int)v62 <= (int)&unk_1048153 )
          {
            if ( (int)v62 > -821242952 )
            {
              if ( (_DWORD)v62 == -821242951 )
              {
                LODWORD(v62) = 591486677;
                if ( v485 < 0x18 )
                  LODWORD(v62) = -1814854309;
              }
              else if ( (_DWORD)v62 == -332055384 )
              {
                *(_QWORD *)&nptr[0] = &v485;
                v485 = 0;
                LODWORD(v62) = -821242951;
              }
            }
            else if ( (_DWORD)v62 == -2112752183 )
            {
              ++v485;
              LODWORD(v62) = -821242951;
            }
            else if ( (_DWORD)v62 == -1814854309 )
            {
              LODWORD(v612) = v485;
              v62 = &unk_1048154;
            }
          }
          if ( (int)v62 > 1831282350 )
            break;
          if ( (_DWORD)v62 == (_DWORD)&unk_1048154 )
          {
            i3 = v485;
            *((_BYTE *)&v399 + v485 + 2) ^= (v612 + 1) ^ BYTE1(v399) ^ 0x18;
            LODWORD(v62) = -2112752183;
          }
          else if ( (_DWORD)v62 == 591486677 )
          {
            i3 = 0;
            v414[0] = 0;
            v414[1] = 0;
            *(_BYTE *)v545 = 0;
            LODWORD(v62) = 1831282351;
          }
        }
        if ( (_DWORD)v62 != 1999295770 )
          break;
        LODWORD(v62) = -332055384;
        if ( (v354 & 1) == 0 )
          LODWORD(v62) = 1831282351;
      }
    }
    while ( (_DWORD)v62 != 1831282351 );
    v281 = (char *)&v399 + 2;
    v48 = 1008413870;
  }
  v271 = (void **)v297;
  v272 = v297 + 2;
  *v297 = v297 + 2;
  if ( v370 == &v372 )
  {
    *v272 = v372;
  }
  else
  {
    *v271 = v370;
    v271[2] = (void *)v372;
  }
  v271[1] = v371;
  v370 = &v372;
  v371 = 0;
  LOBYTE(v372) = 0;
  if ( v368[0] != v369 )
    operator delete(v368[0]);
  if ( v373[0] != &v374 )
    operator delete(v373[0]);
  return v297;
}


// ===== sub_5CE6230 @ 0x5ce6230 (size 0x5dc) =====
unsigned __int64 __fastcall sub_5CE6230(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  __int64 v5; // r11
  unsigned __int64 result; // rax
  int i; // r9d
  unsigned __int64 *v8; // rax
  __int64 v9; // rcx
  __int64 v10; // [rsp+0h] [rbp-A0h] BYREF
  _QWORD *v11; // [rsp+8h] [rbp-98h]
  _QWORD *v12; // [rsp+10h] [rbp-90h]
  _QWORD *v13; // [rsp+18h] [rbp-88h]
  __int64 v14; // [rsp+20h] [rbp-80h]
  __int64 v15; // [rsp+28h] [rbp-78h]
  unsigned __int64 *v16; // [rsp+30h] [rbp-70h]
  unsigned __int64 *v17; // [rsp+38h] [rbp-68h]
  unsigned __int64 *v18; // [rsp+40h] [rbp-60h]
  unsigned __int64 *v19; // [rsp+48h] [rbp-58h]
  unsigned __int64 *v20; // [rsp+50h] [rbp-50h]
  __int64 *v21; // [rsp+58h] [rbp-48h]
  bool v22; // [rsp+65h] [rbp-3Bh]
  bool v23; // [rsp+66h] [rbp-3Ah]
  bool v24; // [rsp+67h] [rbp-39h]
  _QWORD v25[7]; // [rsp+68h] [rbp-38h] BYREF

  result = __readfsqword(0x28u);
  v25[1] = result;
  for ( i = -1079672910; ; i = 355329591 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( i > 411975767 )
          {
            if ( i <= 1471315531 )
            {
              if ( i > 813642876 )
              {
                if ( i > 1062390292 )
                {
                  if ( i != 1062390293 )
                  {
                    v8 = v18;
                    goto LABEL_58;
                  }
                  v5 = v14 >> 2;
                  i = 831509242;
                }
                else if ( i == 813642877 )
                {
LABEL_63:
                  v17 = v25;
                  i = 1471315532;
                  if ( *(_QWORD *)v25[0] == *(_QWORD *)*v21 )
                    i = 1651543371;
                }
                else
                {
                  v15 = v5;
                  i = 2012198253;
                  if ( v5 > 0 )
                    i = 2107605420;
                }
              }
              else if ( i > 714338821 )
              {
                v12 = (_QWORD *)*v20;
                i = 1578746339;
              }
              else
              {
                if ( i == 411975768 )
                  goto LABEL_57;
                v24 = *v13 == *(_QWORD *)*v21;
                i = -90131025;
              }
            }
            else if ( i <= 2012198252 )
            {
              if ( i > 1651543370 )
              {
                if ( i == 1651543371 )
                {
                  v8 = v17;
LABEL_58:
                  result = *v8;
                  i = -462641868;
                }
                else
                {
                  a5 += 8;
                  v25[0] = a5;
                  i = -118024881;
                }
              }
              else if ( i == 1471315532 )
              {
                a5 += 8;
                v25[0] = a5;
                i = -2105298989;
              }
              else
              {
                i = 2050213043;
                if ( *v12 == *(_QWORD *)*v21 )
                  i = 411975768;
              }
            }
            else if ( i <= 2063670150 )
            {
              if ( i == 2012198253 )
              {
                v9 = (__int64)(*v19 - a5) >> 3;
                if ( v9 == 1 )
                  goto LABEL_66;
                if ( v9 == 2 )
                  goto LABEL_63;
                if ( v9 != 3 )
                {
LABEL_56:
                  v8 = v19;
                  goto LABEL_58;
                }
                v18 = v25;
                i = -1994438806;
              }
              else
              {
                a5 += 8;
                v25[0] = a5;
                v5 = v15 - 1;
                i = 831509242;
              }
            }
            else if ( i == 2063670151 )
            {
              v23 = *(_QWORD *)*v20 == *(_QWORD *)*v21;
              i = -781348762;
            }
            else
            {
              if ( i != 2107605420 )
              {
                v8 = v16;
                goto LABEL_58;
              }
              v20 = v25;
              v13 = (_QWORD *)v25[0];
              i = 703909952;
            }
          }
          if ( i > -462641869 )
            break;
          if ( i > -1287611807 )
          {
            if ( i > -995518044 )
            {
              if ( i == -995518043 )
              {
                i = -1667987963;
                if ( *v11 == *(_QWORD *)*v21 )
                  i = 1432514705;
              }
              else
              {
                i = 1798428483;
                if ( v23 )
                  i = -256876433;
              }
            }
            else
            {
              if ( i == -1287611806 )
                goto LABEL_57;
              v19 = (unsigned __int64 *)&v10;
              v21 = &v10 - 2;
              v25[0] = a1;
              v10 = a2;
              *(&v10 - 2) = a3;
              a5 = v25[0];
              v14 = (__int64)(*v19 - v25[0]) >> 3;
              i = 1062390293;
            }
          }
          else if ( i > -1667987964 )
          {
            a5 += 8;
            v25[0] = a5;
            if ( i == -1667987963 )
              i = 813642877;
            else
              i = 714338822;
          }
          else if ( i == -2105298989 )
          {
LABEL_66:
            v16 = v25;
            i = -436087817;
            if ( *(_QWORD *)v25[0] == *(_QWORD *)*v21 )
              i = 2130563704;
          }
          else
          {
            v11 = (_QWORD *)*v18;
            i = -995518043;
          }
        }
        if ( i <= -90131026 )
          break;
        if ( i > 207231441 )
        {
          if ( i != 207231442 )
            goto LABEL_56;
          goto LABEL_57;
        }
        if ( i == -90131025 )
        {
          i = 82365410;
          if ( v24 )
            i = -1287611806;
        }
        else
        {
          a5 += 8;
          v25[0] = a5;
          i = 2063670151;
        }
      }
      if ( i <= -143000603 )
        break;
      if ( i == -143000602 )
      {
        i = -1345956955;
        if ( v22 )
          i = 207231442;
      }
      else
      {
        v22 = *(_QWORD *)*v20 == *(_QWORD *)*v21;
        i = -143000602;
      }
    }
    if ( i != -436087817 )
      break;
    a5 += 8;
    v25[0] = a5;
  }
  if ( i == -256876433 )
  {
LABEL_57:
    v8 = v20;
    goto LABEL_58;
  }
  return result;
}


// ===== sub_5CE6006 @ 0x5ce6006 (size 0x123) =====
unsigned __int64 __fastcall sub_5CE6006(__int64 a1, __int64 a2, __int64 *a3, __int64 a4, __int64 a5)
{
  int i; // eax
  _QWORD *v8; // [rsp+8h] [rbp-50h]
  __int64 v9; // [rsp+18h] [rbp-40h]
  unsigned __int64 v10; // [rsp+20h] [rbp-38h]
  _QWORD v11[6]; // [rsp+28h] [rbp-30h] BYREF

  v11[1] = __readfsqword(0x28u);
  v11[0] = a2;
  for ( i = 798745500; ; i = -1582962914 )
  {
    while ( i > -516094581 )
    {
      if ( i == -516094580 )
      {
        *a3 = (__int64)(v8[1] - *v8) >> 3;
        std::vector<long>::emplace_back<long &>(v8, v11);
        i = -1582962914;
      }
      else if ( i == 1177461696 )
      {
        v10 = sub_5CE6230(v9, v8[1], (__int64)v11, a4, a5);
        a4 = (__int64)v8;
        i = -2063907392;
        if ( v10 == v8[1] )
          i = -516094580;
      }
      else
      {
        v8 = (_QWORD *)(a1 + 32);
        v9 = *(_QWORD *)(a1 + 32);
        i = 1177461696;
      }
    }
    if ( i != -2063907392 )
      break;
    a4 = (__int64)(v10 - *v8) >> 3;
    *a3 = a4;
  }
  return __readfsqword(0x28u);
}
