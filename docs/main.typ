#import "conf.typ": doc, preface, main
#import "components/cover.typ": cover
#import "components/figure.typ": algorithm-figure, code-figure
#import "components/outline.typ": outline-page
#import "@preview/lovelace:0.2.0": *

#show: doc

#set text(lang: "zh", region: "cn")

#cover(
  title: "MinotaurOS",
  institute: "哈尔滨工业大学",
)

#show: preface.with(title: "MinotaurOS")

#outline-page()

#show: main

#include "content/general.typ"
#include "content/memory.typ"
#include "content/process.typ"
#include "content/driver.typ"
#include "content/filesystem.typ"
#include "content/interrupt.typ"
#include "content/signal.typ"
#include "content/net.typ"
#include "content/conclusion.typ"
