package api

import (
	"net/http"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
)

type integrationOrderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

type orderItemResponse struct {
	ProductID   int64  `json:"product_id"`
	ProductName string `json:"product_name"`
	Quantity    int64  `json:"quantity"`
	PriceCents  int64  `json:"price_cents"`
}

type productResponse struct {
	Id          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Image_Path  string `json:"image_path"`
	Price_Cents int64  `json:"price_cents"`
}

type orderResponse struct {
	Id          int64  `json:"id"`
	Status      string `json:"status"`
	Total_Cents int64  `json:"total_cents"`
	Created_At  string `json:"created_at"`
}

type Handler struct {
	accountStore      *accounts.Store
	orderStore        *orders.Store
	productStore      *storefront.Store
	apiStore          *Store
	logger            *logging.Logger
	maxProductResults int64
}

func NewHandler(accountStore *accounts.Store, orderStore *orders.Store, productStore *storefront.Store, apiStore *Store, logger *logging.Logger, maxProductResults int) *Handler {
	return &Handler{
		accountStore: accountStore, orderStore: orderStore, productStore: productStore, apiStore: apiStore,
		logger: logger, maxProductResults: int64(maxProductResults),
	}
}

func (handler *Handler) AccountOrders(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orders, err := handler.orderStore.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	resBody := make([]orderResponse, len(orders))
	for idx, it := range orders {
		resBody[idx] = orderResponse{
			Id:          it.ID,
			Status:      it.Status,
			Total_Cents: it.TotalCents,
			Created_At:  it.CreatedAt,
		}
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"orders": resBody})
}

func (handler *Handler) Order(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orderID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || order.UserID != current.User.ID {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	items, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	itemResponses := make([]orderItemResponse, 0, len(items))
	for _, item := range items {
		itemResponses = append(itemResponses, orderItemResponse{ProductID: item.ProductID, ProductName: item.ProductName, Quantity: item.Quantity, PriceCents: item.PriceCents})
	}
	resBody := make([]orderItemResponse, len(itemResponses))
	for idx, it := range itemResponses {
		resBody[idx] = orderItemResponse{
			ProductID:   it.ProductID,
			ProductName: it.ProductName,
			Quantity:    it.Quantity,
			PriceCents:  it.PriceCents,
		}
	}
	orderRes := orderResponse{
		Id:          order.ID,
		Status:      order.Status,
		Total_Cents: order.TotalCents,
		Created_At:  order.CreatedAt,
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"order": orderRes, "items": resBody})
}

func (handler Handler) OptionsProducts(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "GET")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	httpx.RespondWithJSON(w, http.StatusNoContent, nil)
}

func (handler *Handler) Products(responseWriter http.ResponseWriter, request *http.Request) {
	products, err := handler.productStore.ListAllProducts(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	responseWriter.Header().Add("Access-Control-Allow-Origin", "*")
	responseWriter.Header().Set("Access-Control-Allow-Credentials", "false")
	resBody := []productResponse{}
	for _, it := range products {
		if !it.IsActive {
			continue
		}
		resBody = append(resBody, productResponse{
			Id:          it.ID,
			Name:        it.Name,
			Description: it.Description,
			Image_Path:  it.ImagePath,
			Price_Cents: it.CostCents,
		})
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"products": resBody,
	})
}

func (handler *Handler) WarehouseOrders(responseWriter http.ResponseWriter, request *http.Request) {
	rawApiKey := request.Header.Get("X-API-Key")
	apiKey, ok, err := handler.apiStore.FindKey(request.Context(), rawApiKey)
	if err != nil || !ok {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]any{"error": err})
		return
	}
	if !strings.Contains(apiKey.Scope, "orders:read") {
		httpx.RespondWithJSON(responseWriter, http.StatusForbidden, map[string]any{"error": "Missing read scope"})
		return
	}
	orders, err := handler.orderStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	responses := make([]integrationOrderResponse, 0, len(orders))
	for _, order := range orders {
		responses = append(responses, integrationOrderResponse{
			ID: order.ID, Status: order.Status, TotalCents: order.TotalCents, CreatedAt: order.CreatedAt,
		})
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"integration": "Warehouse Fulfillment Integration",
		"orders":      responses,
	})
}

func (handler *Handler) requireAuthentication(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	httpx.RespondWithError(responseWriter, http.StatusInternalServerError, err.Error())
}
