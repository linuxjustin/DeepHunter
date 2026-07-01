# Bug Bounty Investigation Report: Investigation-bugbounty

## Metadata

- **Target:** vtiger.com
- **Generated:** 2026-07-01T19:08:06.350683+00:00
- **Report ID:** N/A

---

## Executive Summary

This report documents the security investigation of **vtiger.com** performed using DeepHunter.

**Investigation Status:** in_progress
**Session ID:** inv-083413ff8d6e

### Key Metrics
- **Tasks Completed:** 0/289
- **Tasks Failed:** 289
- **Tasks Pending:** 0
- **Evidence Records:** 9
- **Draft Findings:** 0

**Evidence by Type:**
  - observation: 7
  - http_response: 2

This investigation used 1 knowledge packs and 13 methodology packs.

---

## Scope

**Primary Target:** vtiger.com

### In Scope (480 entries)
- `vtiger.com`
- `blog.vtiger.com`
- `blogs.vtiger.com`
- `discussions.vtiger.com`
- `dns-admin.vtiger.com`
- `vis9-usnv.od2.vtiger.com`
- `visvip3-usnv.od1.vtiger.com`
- `vmds-sg.vtiger.com`
- `zlc.od1.vtiger.com`
- `centocinquanta.od1.vtiger.com`
- `cooritalia.od2.vtiger.com`
- `vdi2-usnv.od2.vtiger.com`
- `domain.vtiger.com`
- `landtours.od1.vtiger.com`
- `accolent.od2.vtiger.com`
- `kaperscadcam1.od2.vtiger.com`
- `ecm-bounces.vtiger.com`
- `ftstx.vtiger.com`
- `sv2gate.vtiger.com`
- `pentagontechnicalservices1.od2.vtiger.com`
- `sithappensdogtraining.od2.vtiger.com`
- `sixbell-crm.od2.vtiger.com`
- `teamsos.od2.vtiger.com`
- `crmaccounts.vtiger.com`
- `od2.vtiger.com`
- `spf1.vtiger.com`
- `euris.od1.vtiger.com`
- `forge.vtiger.com`
- `u003ecode.vtiger.com`
- `ocr.vtiger.com`
- `simplecell.od1.vtiger.com`
- `digitickets.od2.vtiger.com`
- `specializedcommunications.od1.vtiger.com`
- `vanuston3.od2.vtiger.com`
- `h2bc.od2.vtiger.com`
- `prodwin.od2.vtiger.com`
- `iceptstechnologygroupinc1.od1.vtiger.com`
- `shinka1.od2.vtiger.com`
- `fbredir.od1.vtiger.com`
- `company132818.od2.vtiger.com`
- `redlandsmodernmusicclubinc.od2.vtiger.com`
- `maps.forge.vtiger.com`
- `fondazione.od2.vtiger.com`
- `theresilienceproject.od2.vtiger.com`
- `digitalprodoo.od1.vtiger.com`
- `ewsn1p.vtiger.com`
- `sintratecgmbh.od1.vtiger.com`
- `vdns.od2.vtiger.com`
- `company1233577.od2.vtiger.com`
- `techfusion.od1.vtiger.com`
- `finchsolues.od2.vtiger.com`
- `universidadadventistadelplata1.od2.vtiger.com`
- `hetzner1.vtiger.com`
- `uandunl.od1.vtiger.com`
- `vdi1-asiasg.od2.vtiger.com`
- `mitsco.od2.vtiger.com`
- `firestorm.od1.vtiger.com`
- `openfoodnetwork1.od2.vtiger.com`
- `conformisinfinancesrl.od1.vtiger.com`
- `ndovucloudcrm.od2.vtiger.com`
- `vmds-aus.vtiger.com`
- `company12343945.od2.vtiger.com`
- `bmindco.od1.vtiger.com`
- `businesscase.forge.vtiger.com`
- `myhome24.od2.vtiger.com`
- `activetelephonedata.od2.vtiger.com`
- `community.vtiger.com`
- `notifier.vtiger.com`
- `vis2-eufrf.od2.vtiger.com`
- `nativadigital1.od2.vtiger.com`
- `ngportal.vtiger.com`
- `openfoodfrance1.od2.vtiger.com`
- `sunshinegolf.od2.vtiger.com`
- `therecordingconservatoryofaustin.od2.vtiger.com`
- `productsinnovationgroupinc.od2.vtiger.com`
- `vis2-eufrf.od1.vtiger.com`
- `company1233437.od2.vtiger.com`
- `company13775.od2.vtiger.com`
- `mdsiaamar.od2.vtiger.com`
- `drivepickervault.vtiger.com`
- `ns1.staging-rnd.od1.vtiger.com`
- `vis5-euir.od2.vtiger.com`
- `freesmile1.od2.vtiger.com`
- `netwirefiberinc.od2.vtiger.com`
- `germanlang.forge.vtiger.com`
- `zoomusic4.od2.vtiger.com`
- `mad5.od1.vtiger.com`
- `company14269.od2.vtiger.com`
- `intelligentdesigns1.od1.vtiger.com`
- `mta-sts.vtiger.com`
- `tecnosoft.od1.vtiger.com`
- `ns1.vtiger.com`
- `websense.vtiger.com`
- `protectipglobalsolutions.od1.vtiger.com`
- `timetrak.od2.vtiger.com`
- `bglang.forge.vtiger.com`
- `msteamsapp.vtiger.com`
- `u003ewww.vtiger.com`
- `emcan3.vtiger.com`
- `whisper.vtiger.com`
- `nextlevelstoragesolutions.od1.vtiger.com`
- `neksugbr.od2.vtiger.com`
- `baldinistudiohr.od1.vtiger.com`
- `vmds-disaster.vtiger.com`
- `vmds-jp.vtiger.com`
- `motiq.od2.vtiger.com`
- `stantonchase1.od2.vtiger.com`
- `mail.od2.vtiger.com`
- `crmaccess.vtiger.com`
- `ginlongusa.od1.vtiger.com`
- `login.vtiger.com`
- `tetosvoso.forge.vtiger.com`
- `dis1-usnv.od2.vtiger.com`
- `sesamosrl.od2.vtiger.com`
- `langpack-frca.forge.vtiger.com`
- `phplistsync.forge.vtiger.com`
- `vgcal.forge.vtiger.com`
- `pricelessparenting.od1.vtiger.com`
- `stelarsrl.od1.vtiger.com`
- `tradejini1.od2.vtiger.com`
- `fieldxinc.od2.vtiger.com`
- `fmlcuslugadoo1.od1.vtiger.com`
- `grc2020researchllc.od2.vtiger.com`
- `alfait-outsourcinggmbh.od2.vtiger.com`
- `caarrslimited.od2.vtiger.com`
- `nylesystems1.od2.vtiger.com`
- `academy.vtiger.com`
- `hostmaster-pdnsca2.vtiger.com`
- `spftx.vtiger.com`
- `umbrellagwent.od2.vtiger.com`
- `algoe3.od2.vtiger.com`
- `signaliseco-op1.od2.vtiger.com`
- `allsysinc.od1.vtiger.com`
- `amwgroup.od2.vtiger.com`
- `gbadvisors.od1.vtiger.com`
- `geoip.vtiger.com`
- `vcapi.vtiger.com`
- `vts-projects.forge.vtiger.com`
- `ircrelocation.od2.vtiger.com`
- `unioncommunity1.od1.vtiger.com`
- `vis1-asiamb.od2.vtiger.com`
- `4esusa.od2.vtiger.com`
- `contex.od2.vtiger.com`
- `kentusacrm.od2.vtiger.com`
- `unikaksha.od2.vtiger.com`
- `en.vtiger.com`
- `forum.vtiger.com`
- `helpdocs.vtiger.com`
- `reach22.od1.vtiger.com`
- `skytelsystems1.od1.vtiger.com`
- `truevoice.od1.vtiger.com`
- `procreatechsrl2.od2.vtiger.com`
- `teksalahcrm.od2.vtiger.com`
- `grupocuesa.od2.vtiger.com`
- `apsei.od1.vtiger.com`
- `vtester.forge.vtiger.com`
- `vtap.vtiger.com`
- `cwc.forge.vtiger.com`
- `support.vtiger.com`
- `tredasolutions.od2.vtiger.com`
- `unircuidadores.od1.vtiger.com`
- `gembasolutionsltd.od2.vtiger.com`
- `analytica1.od2.vtiger.com`
- `pdfmakerfree.forge.vtiger.com`
- `vtdg.forge.vtiger.com`
- `datasystem.od2.vtiger.com`
- `vchatbot.vtiger.com`
- `breezway4.od1.vtiger.com`
- `lang-pack-fr-ca.forge.vtiger.com`
- `penaviation.od2.vtiger.com`
- `gemhorninc.od1.vtiger.com`
- `demo.vtiger.com`
- `vmds-eu.vtiger.com`
- `secretscreen1.od2.vtiger.com`
- `es.vtiger.com`
- `mail.vtiger.com`
- `mtap.od2.vtiger.com`
- `ultimate.od1.vtiger.com`
- `hijosdeluisrodrguez.od2.vtiger.com`
- `richie.vtiger.com`
- `aurikinvestmentholdingsed1.od1.vtiger.com`
- `jackhealingchurchtv.od2.vtiger.com`
- `mc2.od2.vtiger.com`
- `renewskinandhealthclinicltd.od2.vtiger.com`
- `company1233914.od2.vtiger.com`
- `diggmbh3.od2.vtiger.com`
- `devop2.vtiger.com`
- `vtlib.forge.vtiger.com`
- `paragonnetworks.od1.vtiger.com`
- `mrx17.od2.vtiger.com`
- `oldmarketplace.vtiger.com`
- `vis5-eufrf.od2.vtiger.com`
- `fortunysrl.od2.vtiger.com`
- `11stats.vtiger.com`
- `aicaengineeringindiapvyltd.od1.vtiger.com`
- `teleport.vtiger.com`
- `copysiel.od2.vtiger.com`
- `floridamanstoys.od2.vtiger.com`
- `vis3-eufrf.od2.vtiger.com`
- `aultech1.od2.vtiger.com`
- `donalbaelectronicasl.od2.vtiger.com`
- `stats.vtiger.com`
- `vtmailscanner.forge.vtiger.com`
- `netjapan.od2.vtiger.com`
- `sapiensenergia.od2.vtiger.com`
- `thecrag.od2.vtiger.com`
- `vis1-sg.od2.vtiger.com`
- `vtiger6examples.forge.vtiger.com`
- `vtjoomla.forge.vtiger.com`
- `cercal.od2.vtiger.com`
- `growyourbiz3.od1.vtiger.com`
- `spiraltrain1.od1.vtiger.com`
- `reseller.vtiger.com`
- `rofsky.od2.vtiger.com`
- `evolucioninformaticahotelerasl.od1.vtiger.com`
- `nexuscom.od2.vtiger.com`
- `visvip1-asiasg.od1.vtiger.com`
- `filwww.vtiger.com`
- `iqualifyuk1.od2.vtiger.com`
- `oauthredir.od1.vtiger.com`
- `rockachee1.od1.vtiger.com`
- `c1net.od2.vtiger.com`
- `surveys.vtiger.com`
- `handappssoftwareinc.od1.vtiger.com`
- `avadesigntechnologycoltd.od2.vtiger.com`
- `sls.vtiger.com`
- `vis2-sg.od2.vtiger.com`
- `company1234167.od2.vtiger.com`
- `eddigital.od2.vtiger.com`
- `cargomagazine.od2.vtiger.com`
- `ebiexperts.od2.vtiger.com`
- `bugs.vtiger.com`
- `rtrdigitalllc.od2.vtiger.com`
- `server.vtiger.com`
- `vdi2-asiasg.od2.vtiger.com`
- `vis1-eufrf.od2.vtiger.com`
- `vquickedit.forge.vtiger.com`
- `centrovirtualempresarial.od1.vtiger.com`
- `gms14.od2.vtiger.com`
- `saince.od1.vtiger.com`
- `n7cg.od2.vtiger.com`
- `demozap.vtiger.com`
- `vtigerecs.od1.vtiger.com`
- `vttb3.forge.vtiger.com`
- `websitetalkingheads.od1.vtiger.com`
- `restaurantlacucanyasa1.od2.vtiger.com`
- `triggertechnologysystems.od1.vtiger.com`
- `istnetgroup.od2.vtiger.com`
- `trellisworkslimited.od2.vtiger.com`
- `company12344119.od2.vtiger.com`
- `testingvt.forge.vtiger.com`
- `webtrack.vtiger.com`
- `www.vtiger.com`
- `jsdns.vtiger.com`
- `smtpca.vtiger.com`
- `chapterthree.od1.vtiger.com`
- `highresmediallc.od1.vtiger.com`
- `planetassociatesinc.od1.vtiger.com`
- `etic5.od2.vtiger.com`
- `odamigo1.od2.vtiger.com`
- `cloudquantcapitalmanagement.od2.vtiger.com`
- `enquirieseximportcomau.od2.vtiger.com`
- `discussion.vtiger.com`
- `sidexfundingsolutions.od2.vtiger.com`
- `pdnsnv1.vtiger.com`
- `polotecnologicodipordenone.od2.vtiger.com`
- `vdi1-euir.od1.vtiger.com`
- `api.vtiger.com`
- `guides.vtiger.com`
- `powerwise.od1.vtiger.com`
- `wiki.vtiger.com`
- `civprelastirosealeco.od2.vtiger.com`
- `latintrails.od2.vtiger.com`
- `vis3-euir.od2.vtiger.com`
- `douglasfishercreative.od2.vtiger.com`
- `indiamanthan4.od2.vtiger.com`
- `kuwaitdigitaltechnologies.od2.vtiger.com`
- `extensionloader.forge.vtiger.com`
- `ondemand.vtiger.com`
- `adaptmyhome.od2.vtiger.com`
- `sipbb1.od2.vtiger.com`
- `crm.vtiger.com`
- `ascompag.od2.vtiger.com`
- `code.vtiger.com`
- `aurikinvestmentholdings.od1.vtiger.com`
- `3pltotal.od2.vtiger.com`
- `skymarketing38.od2.vtiger.com`
- `slido2.od2.vtiger.com`
- `hlrvip-euir.od1.vtiger.com`
- `atlanticuniversitycollege.od2.vtiger.com`
- `code2.vtiger.com`
- `status.vtiger.com`
- `propertypursuit.od2.vtiger.com`
- `two.vtiger.com`
- `usp.od2.vtiger.com`
- `velos.od1.vtiger.com`
- `reddendirect.od1.vtiger.com`
- `excursy.od2.vtiger.com`
- `vsm.od2.vtiger.com`
- `mkinfraholdingsprivatelimited.od2.vtiger.com`
- `rb3d1.od2.vtiger.com`
- `smartinvestments.od2.vtiger.com`
- `xyz.vtiger.com`
- `emcan1.vtiger.com`
- `explorer260.od2.vtiger.com`
- `falcon.vtiger.com`
- `itsvietnam1.od2.vtiger.com`
- `knowtiongmbh.od2.vtiger.com`
- `launtelnetau.od2.vtiger.com`
- `vis7-euir.od2.vtiger.com`
- `autoartisan.od2.vtiger.com`
- `darklordbrewery.od2.vtiger.com`
- `vttwitter.forge.vtiger.com`
- `rudragnyaconsultantsprivatelimited.od2.vtiger.com`
- `textmercato.od2.vtiger.com`
- `aicainternationalptyltd.od1.vtiger.com`
- `trac.vtiger.com`
- `vis1-usnv.od2.vtiger.com`
- `charter.vtiger.com`
- `vis1-eufrf.od1.vtiger.com`
- `grasspods-doc.od2.vtiger.com`
- `ktc7.od2.vtiger.com`
- `download.vtiger.com`
- `netwire.od2.vtiger.com`
- `ticare.od2.vtiger.com`
- `ftp.vtiger.com`
- `vtwsclib.forge.vtiger.com`
- `diessemediazionecreditiziasrl.od2.vtiger.com`
- `finessenergy.od2.vtiger.com`
- `emcan2.vtiger.com`
- `lifesensors.od2.vtiger.com`
- `ftstx-us1.vtiger.com`
- `mail1.vtiger.com`
- `oceanwiselimited.od1.vtiger.com`
- `cowww.vtiger.com`
- `gelisim.od1.vtiger.com`
- `hiltonsantamarta.od2.vtiger.com`
- `luvinajsc.od2.vtiger.com`
- `voeyenew.vtiger.com`
- `boekel.od1.vtiger.com`
- `instantgmpinc5.od2.vtiger.com`
- `pdnsca2.vtiger.com`
- `assetintigratedinfosystems.od2.vtiger.com`
- `orfsrl.od2.vtiger.com`
- `adverbis.od1.vtiger.com`
- `menconi.od1.vtiger.com`
- `vmds-eufrf.vtiger.com`
- `123mdsdemoptyltd.od2.vtiger.com`
- `digitalynextsrl.od2.vtiger.com`
- `skyguardiantechnology1.od2.vtiger.com`
- `synergyalliance.od2.vtiger.com`
- `mail.od1.vtiger.com`
- `vmds-us.vtiger.com`
- `cirqlive.od2.vtiger.com`
- `comunitpapagiovannixxiii.od1.vtiger.com`
- `vtigerpersian.forge.vtiger.com`
- `brownhudson.od2.vtiger.com`
- `company14441.od2.vtiger.com`
- `nilkamalpeopleocityin.od2.vtiger.com`
- `wirelessnetwaretechnology3.od2.vtiger.com`
- `mx.mail.od1.vtiger.com`
- `vis8-usnv.od2.vtiger.com`
- `vtestmail.od2.vtiger.com`
- `vis1-asiajp.od2.vtiger.com`
- `wildcard.vtiger.com`
- `northeasttechnologies.od1.vtiger.com`
- `dyadent2.od1.vtiger.com`
- `crmaccountsso.vtiger.com`
- `tadiplustelecomgmbh.od2.vtiger.com`
- `cleaningwizard.od2.vtiger.com`
- `lausgroupofcompanies.od2.vtiger.com`
- `seceon.od2.vtiger.com`
- `vdns1.od2.vtiger.com`
- `clevenergysrl.od2.vtiger.com`
- `outsourcedcio.od2.vtiger.com`
- `vis1-euir.od2.vtiger.com`
- `phoenixgeeksllc1.od2.vtiger.com`
- `sevenmentor1.od2.vtiger.com`
- `oculusip.od1.vtiger.com`
- `vmds-ecs.vtiger.com`
- `gbell.od2.vtiger.com`
- `gopal.vtiger.com`
- `gantech.od1.vtiger.com`
- `italian-lang.forge.vtiger.com`
- `lists.forge.vtiger.com`
- `mailchimp.forge.vtiger.com`
- `varma1804-vis1-do-asisasg.od2.vtiger.com`
- `vmds-spbus.vtiger.com`
- `vmds-staging.vtiger.com`
- `vtigerfinnish.forge.vtiger.com`
- `propertystewards.od2.vtiger.com`
- `rta5.od2.vtiger.com`
- `vis1-asiasg.od2.vtiger.com`
- `hlrvip-eufrf.od2.vtiger.com`
- `static-vtc.vtiger.com`
- `demonew.vtiger.com`
- `in516ht1.od2.vtiger.com`
- `lefict.od2.vtiger.com`
- `extend.vtiger.com`
- `ns2.vtiger.com`
- `pf13.od2.vtiger.com`
- `enhancewf.forge.vtiger.com`
- `cvtlogin2.vtiger.com`
- `gilmancocpasllc.od1.vtiger.com`
- `high-liftdoorinc.od2.vtiger.com`
- `miethealthcare1.od2.vtiger.com`
- `vical.forge.vtiger.com`
- `vtheatwavepoc.od2.vtiger.com`
- `vtigerdesignsystem.vtiger.com`
- `alfalogistika.od2.vtiger.com`
- `vtextensions.forge.vtiger.com`
- `livingroomtheaters.od2.vtiger.com`
- `compu-datainternationalllc1.od1.vtiger.com`
- `globalpresencenetwork.od2.vtiger.com`
- `vquickbooks.forge.vtiger.com`
- `diagnosticbiosystems2.od2.vtiger.com`
- `dlink.od2.vtiger.com`
- `accordioltd2.od2.vtiger.com`
- `accounts.od2.vtiger.com`
- `skybusinesscentres.od1.vtiger.com`
- `jobs.vtiger.com`
- `vislt1-eufrf.od2.vtiger.com`
- `titanbiotechlimited.od2.vtiger.com`
- `edservicesptyltd1.od2.vtiger.com`
- `filesaversdatarecovery.od1.vtiger.com`
- `appl3.od2.vtiger.com`
- `forums.vtiger.com`
- `host-itltd1.od2.vtiger.com`
- `iplannerinc1.od1.vtiger.com`
- `diocesan1.od2.vtiger.com`
- `od1.vtiger.com`
- `crmaccounts.od1.vtiger.com`
- `wnt.od2.vtiger.com`
- `altiussportsandleisurepvtltd.od2.vtiger.com`
- `docs.vtiger.com`
- `marketplace.vtiger.com`
- `mta-sts.forge.vtiger.com`
- `ex-importnicheproducts.od2.vtiger.com`
- `partnershu.od2.vtiger.com`
- `ppp23.od2.vtiger.com`
- `files.vtiger.com`
- `ecc.od2.vtiger.com`
- `help.vtiger.com`
- `vtwschromer.forge.vtiger.com`
- `ateliernumerique.od1.vtiger.com`
- `amsysgmbh.od1.vtiger.com`
- `peptechbiosciencesltd.od2.vtiger.com`
- `thehopestreettheatre.od2.vtiger.com`
- `crm-now-pdf.forge.vtiger.com`
- `subzeroicecream1.od2.vtiger.com`
- `highveldtaxidermists.od1.vtiger.com`
- `enesens.od2.vtiger.com`
- `innovaertechnologies.od2.vtiger.com`
- `lifecare.od2.vtiger.com`
- `eventplus1.od2.vtiger.com`
- `vis4-eufrf.od2.vtiger.com`
- `aptosolutionslimited2.od2.vtiger.com`
- `demo2.vtiger.com`
- `lifebook.od1.vtiger.com`
- `odusage.vtiger.com`
- `canadacredit.od2.vtiger.com`
- `dcdreamcenter.od2.vtiger.com`
- `insuringfla.vtiger.com`
- `vmds-mb.vtiger.com`
- `gbsoxford.od2.vtiger.com`
- `core.vtiger.com`
- `pedcoag.od2.vtiger.com`
- `vis6-euir.od2.vtiger.com`
- `cvtlogin1.vtiger.com`
- `cetysuniversidad2.od2.vtiger.com`
- `iotsolution.od2.vtiger.com`
- `qteserviceundsystemegmbh.od2.vtiger.com`
- `ftstx-aus1.vtiger.com`
- `arquitecturayconcreto.od2.vtiger.com`
- `mihau87.forge.vtiger.com`
- `sbeprocurementcompliance.od2.vtiger.com`
- `centrodeestudiosbiosanitarios.od1.vtiger.com`
- `handbookgermanytogether.od2.vtiger.com`
- `globalcrm.od1.vtiger.com`
- `devalyze.od2.vtiger.com`

### Technologies Detected
Angular, Apache, Bootstrap, jQuery

---

## Reconnaissance Summary

**Total Recon Artifacts:** 9

**Technologies Identified:** 4

### Sample Findings
- **In-scope target: vtiger.com**: In-scope target: vtiger.com...
- **In-scope target: vtiger.com**: In-scope target: vtiger.com...
- **Attack surface entry: vtiger.com (in_scope)**: Attack surface entry: vtiger.com (in_scope)...
- **Identified technology: Angular**: Identified technology: Angular...
- **Identified technology: Apache**: Identified technology: Apache...

_... and 4 more artifacts_

---

## Technology Profile

### Identified Technologies

`Angular`, `Apache`, `Bootstrap`, `jQuery`

---

## Attack Surface Summary

**Total Evidence Records:** 9
**Total Tasks:** 289

### Evidence by Category
- **observation:** 7
- **http_response:** 2

### Tasks by Category
- **api:** 0/38 completed
- **authentication:** 0/79 completed
- **authorization:** 0/22 completed
- **business_logic:** 0/7 completed
- **cloud:** 0/5 completed
- **file_upload:** 0/5 completed
- **graphql:** 0/15 completed
- **other:** 0/94 completed
- **rce:** 0/11 completed
- **recon:** 0/2 completed
- **session:** 0/3 completed
- **ssrf:** 0/8 completed

---

## Methodology Applied

### Knowledge Packs Applied
- `apache`

### Methodology Packs Applied
- `GraphQL`
- `REST API`
- `OAuth`
- `OIDC`
- `JWT`
- `Session Management`
- `File Upload`
- `Business Logic`
- `Cloud Review`
- `Microservices`
- `Command Injection`
- `Race Conditions`
- `SSRF`

---

## Investigation Timeline

| Event | Details |
|--------|---------|
| Investigation Started | 2026-07-01T19:07:19.732496+00:00 |
| Current Status | in_progress |
| Last Updated | 2026-07-01T19:08:06.349786+00:00 |
| Session ID | inv-083413ff8d6e |
| Steps Completed | 15 |
|   - build_context | completed |
|   - interactive_review | completed |
|   - execute_tasks | completed |
|   - collect_evidence | completed |
|   - draft_report | completed |

| Tasks Total | 289 |
| Tasks Completed | 0 |
| Tasks Failed | 289 |
| Tasks Pending | 0 |

---

## Evidence Collected

### Http Response (2)
- **Evidence: Target vtiger.com is in scope for investigation**: Target vtiger.com is in scope for investigation...
- **Evidence: Target vtiger.com is in scope for investigation**: Target vtiger.com is in scope for investigation...

### Observation (7)
- **In-scope target: vtiger.com**: In-scope target: vtiger.com...
- **In-scope target: vtiger.com**: In-scope target: vtiger.com...
- **Attack surface entry: vtiger.com (in_scope)**: Attack surface entry: vtiger.com (in_scope)...
- **Identified technology: Angular**: Identified technology: Angular...
- **Identified technology: Apache**: Identified technology: Apache...
- **Identified technology: Bootstrap**: Identified technology: Bootstrap...
- **Identified technology: jQuery**: Identified technology: jQuery...


---

## Draft Findings

*No findings drafted.*


---

## Open Questions

*No open questions.*


---

## Suggested Manual Tests

*No manual tests suggested.*


---

## References

- apache

---

*Report generated by DeepHunter on 2026-07-01T19:08:06.350683+00:00*