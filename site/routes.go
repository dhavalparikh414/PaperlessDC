package site

import (
	"net/http"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route
//type rootHandler func(http.ResponseWriter, *http.Request)error
var routes = Routes{
	Route{
		"Signup",
		"POST",
		"/signup",
		SignupHandler,
	},
	Route{
		"Signin",
		"POST",
		"/signin",
		SigninHandler,
	},
	Route{
		"ForgotPassword",
		"POST",
		"/Forgotpassword",
		ForgotPasswordHandler,
	},
	/*
		Route{
			"RRTGet",
			"GET",
			"/rrt",
			RRTGet,
		},
		Route{
			"ResourceList",
			"GET",
			"/list",
			RList,
		},
		Route{
			"MyReservations",
			"GET",
			"/me/{user}",
			MyReservations,
		},

		Route{
			"ResourcesInfo",
			"GET",
			"/info/{resource}",
			ShowResource,
		},
		Route{
			"ResourcesInfoDate",
			"GET",
			"/info/{resource}/{dd}/{mm}/{yyyy}",
			ShowResourceDate,
		},
		Route{
			"MyResourcesDelete",
			"DELETE",
			"/cancel/{user}",
			RemoveMyReservation,
		},
		Route{
			"MyResourcesUpdate",
			"PUT",
			"/update/{user}/{res}",
			SetMyReservation,
		},
		Route{
			"History",
			"GET",
			"/history",
			ShowHistory,
		}
	*/
}
