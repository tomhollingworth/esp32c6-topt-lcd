SET(SOURCES ui_Screen1.c
    ui.c
    ui_comp_hook.c
    ui_helpers.c
    ui_img_gitlab_icon_60x58_png.c
    ui_img_wifi_png.c
    ui_img_wifioff_png.c)

add_library(ui ${SOURCES})
