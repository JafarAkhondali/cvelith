from django.core.management.base import BaseCommand
import pandas as pd
from django.db import connection
from gluonts.dataset.common import ListDataset
from gluonts.torch.model.deepar import DeepAREstimator
from gluonts.evaluation import make_evaluation_predictions
from gluonts.evaluation.backtest import Evaluator
import matplotlib.pyplot as plt
from tqdm import tqdm
import pandas as pd
from django.db import connection
from gluonts.dataset.common import ListDataset
from gluonts.torch.model.deepar import DeepAREstimator
from gluonts.dataset.pandas import PandasDataset
from gluonts.dataset.split import split
from gluonts.torch import DeepAREstimator
import matplotlib.pyplot as plt
from tqdm import tqdm
import pandas as pd
import matplotlib.pyplot as plt
from gluonts.dataset.pandas import PandasDataset
from gluonts.dataset.split import split
from gluonts.torch import DeepAREstimator
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import xgboost as xgb
from scipy import stats
import psycopg2
from psycopg2 import sql


def fetch_cve_df():
    with connection.cursor() as cursor:
        cursor.execute("""
        WITH first_interaction AS (
  SELECT
    cve_id,
    MIN(interacted_time::date) AS first_date
  FROM ghp_with_time
  GROUP BY cve_id
),
interactions_daily_relative AS (
  SELECT
    gwt.cve_id,
    (gwt.interacted_time::date - fi.first_date) AS day_offset,
    gwt.interacted_time::date AS interaction_day
  FROM ghp_with_time gwt
  JOIN first_interaction fi ON gwt.cve_id = fi.cve_id
  WHERE gwt.interacted_time::date >= fi.first_date
),
daily_counts AS (
  SELECT
    cve_id,
    interaction_day,
    COUNT(*) AS interactions
  FROM interactions_daily_relative
  GROUP BY cve_id, interaction_day
),
cve_meta_filtered AS (
  SELECT
    id AS cve_id,
    date_reserved,
    CASE
      WHEN date_reserved BETWEEN '2018-01-01' AND '2023-12-31' THEN 'train'
      WHEN date_reserved >= '2024-01-01' THEN 'test'
      ELSE 'ignore'
    END AS set_type
  FROM cve_cve
)
SELECT
  d.cve_id,
  d.interaction_day,
  d.interactions,
  cmf.date_reserved,
  cmf.set_type
FROM daily_counts d
JOIN cve_meta_filtered cmf ON d.cve_id = cmf.cve_id
WHERE cmf.set_type != 'ignore'
-- ORDER BY interactions desc ;
ORDER BY cmf.set_type, d.cve_id, d.interaction_day;
        """)
        columns = [col[0] for col in cursor.description]
        return pd.DataFrame(cursor.fetchall(), columns=columns)



def train_and_predict():
    pass

class Command(BaseCommand):
    help = "Predict popularity of CVEs based on PoCs"

    def handle(self, *args, **options):

        # Use the exact fetch_cve_df function as provided
        def fetch_cve_df():
            with connection.cursor() as cursor:
                cursor.execute("""
                WITH first_interaction AS (
          SELECT
            cve_id,
            MIN(interacted_time::date) AS first_date
          FROM ghp_with_time
          GROUP BY cve_id
        ),
        interactions_daily_relative AS (
          SELECT
            gwt.cve_id,
            (gwt.interacted_time::date - fi.first_date) AS day_offset,
            gwt.interacted_time::date AS interaction_day
          FROM ghp_with_time gwt
          JOIN first_interaction fi ON gwt.cve_id = fi.cve_id
          WHERE gwt.interacted_time::date >= fi.first_date
        ),
        daily_counts AS (
          SELECT
            cve_id,
            interaction_day,
            COUNT(*) AS interactions
          FROM interactions_daily_relative
          GROUP BY cve_id, interaction_day
        ),
        cve_meta_filtered AS (
          SELECT
            id AS cve_id,
            date_reserved,
            CASE
              WHEN date_reserved BETWEEN '2018-01-01' AND '2023-12-31' THEN 'train'
              WHEN date_reserved >= '2024-01-01' THEN 'test'
              ELSE 'ignore'
            END AS set_type
          FROM cve_cve
        )
        SELECT
          d.cve_id,
          d.interaction_day,
          d.interactions,
          cmf.date_reserved,
          cmf.set_type
        FROM daily_counts d
        JOIN cve_meta_filtered cmf ON d.cve_id = cmf.cve_id
        WHERE cmf.set_type != 'ignore'
        -- ORDER BY interactions desc ;
        ORDER BY cmf.set_type, d.cve_id, d.interaction_day;
                """)
                columns = [col[0] for col in cursor.description]
                return pd.DataFrame(cursor.fetchall(), columns=columns)

        # Get data directly from your SQL query
        df = fetch_cve_df()

        # Data exploration and preprocessing
        print(f"Dataset shape: {df.shape}")
        print("\nData types:")
        print(df.dtypes)
        print("\nSample data:")
        print(df.head())

        # Convert date columns to datetime if they're not already
        if not pd.api.types.is_datetime64_any_dtype(df['interaction_day']):
            df['interaction_day'] = pd.to_datetime(df['interaction_day'])
        if not pd.api.types.is_datetime64_any_dtype(df['date_reserved']):
            df['date_reserved'] = pd.to_datetime(df['date_reserved'])

        # Check for missing values
        print("\nMissing values:")
        print(df.isnull().sum())

        # Basic statistics
        print("\nBasic statistics:")
        print(df.describe())

        # Number of unique CVEs
        print(f"\nNumber of unique CVEs: {df['cve_id'].nunique()}")
        print(f"Number of CVEs in train set: {df[df['set_type'] == 'train']['cve_id'].nunique()}")
        print(f"Number of CVEs in test set: {df[df['set_type'] == 'test']['cve_id'].nunique()}")

        # Feature engineering
        print("\nPerforming feature engineering...")

        # Temporal features
        df['day_of_week'] = df['interaction_day'].dt.dayofweek
        df['month'] = df['interaction_day'].dt.month
        df['year'] = df['interaction_day'].dt.year
        df['quarter'] = df['interaction_day'].dt.quarter
        df['week_of_year'] = df['interaction_day'].dt.isocalendar().week
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)

        # Time-based features
        df['days_since_reserved'] = (df['interaction_day'] - df['date_reserved']).dt.days
        df['weeks_since_reserved'] = df['days_since_reserved'] // 7

        # Logarithmic transformation of time since reserved (captures decay patterns)
        df['log_days_since_reserved'] = np.log1p(df['days_since_reserved'])

        # Create features related to CVE history
        cve_stats = df.groupby('cve_id').agg(
            total_interactions=('interactions', 'sum'),
            mean_interactions=('interactions', 'mean'),
            max_interactions=('interactions', 'max'),
            min_interactions=('interactions', 'min'),
            std_interactions=('interactions', 'std'),
            median_interactions=('interactions', 'median'),
            interaction_days=('interaction_day', 'count'),
            first_interaction_date=('interaction_day', 'min'),
            last_interaction_date=('interaction_day', 'max')
        ).reset_index()

        # Add derived features to the stats
        cve_stats['interaction_span_days'] = (
                    cve_stats['last_interaction_date'] - cve_stats['first_interaction_date']).dt.days
        cve_stats['avg_daily_volume'] = cve_stats['total_interactions'] / cve_stats['interaction_span_days'].replace(0,
                                                                                                                     1)
        cve_stats['interaction_density'] = cve_stats['total_interactions'] / cve_stats['interaction_days']

        # Add CVE characteristics to main dataframe
        df = df.merge(cve_stats, on='cve_id', how='left')

        # Replace NaN values in std with 0 (for CVEs with only one interaction)
        df['std_interactions'] = df['std_interactions'].fillna(0)

        # Add features related to date_reserved
        reserved_year = df['date_reserved'].dt.year
        reserved_month = df['date_reserved'].dt.month
        df['reserved_year'] = reserved_year
        df['reserved_month'] = reserved_month
        df['reserved_quarter'] = df['date_reserved'].dt.quarter

        # Time since first observed interaction
        df['days_since_first_interaction'] = (df['interaction_day'] - df['first_interaction_date']).dt.days

        # CVE interaction velocity (current day's interactions / average interactions so far)
        df['interaction_velocity'] = df['interactions'] / df['mean_interactions'].replace(0, 1)

        # Create lag features for time series analysis
        def add_lag_features(df, group_col, target_col, lags=[1, 2, 3, 7]):
            group = df.groupby(group_col)
            for lag in lags:
                df[f'{target_col}_lag_{lag}'] = group[target_col].shift(lag)
            return df

        # Sort by CVE and date before adding lag features
        df = df.sort_values(['cve_id', 'interaction_day'])
        df = add_lag_features(df, 'cve_id', 'interactions')

        # Fill missing values for lag features
        lag_cols = [col for col in df.columns if 'lag' in col]
        df[lag_cols] = df[lag_cols].fillna(0)

        # Split into train and test sets (using the set_type column from your SQL query)
        train_df = df[df['set_type'] == 'train'].copy()
        test_df = df[df['set_type'] == 'test'].copy()

        print(f"\nTrain set shape: {train_df.shape}")
        print(f"Test set shape: {test_df.shape}")

        # Prepare features and target
        feature_cols = [
            # Temporal features
            'day_of_week', 'month', 'year', 'quarter', 'week_of_year', 'is_weekend',

            # Time since reservation
            'days_since_reserved', 'weeks_since_reserved', 'log_days_since_reserved',

            # CVE statistics
            'mean_interactions', 'max_interactions', 'min_interactions',
            'std_interactions', 'median_interactions', 'interaction_days',
            'interaction_span_days', 'avg_daily_volume', 'interaction_density',

            # Reservation date features
            'reserved_year', 'reserved_month', 'reserved_quarter',

            # Time since first interaction
            'days_since_first_interaction',

            # Interaction velocity
            'interaction_velocity',

            # Lag features
            'interactions_lag_1', 'interactions_lag_2', 'interactions_lag_3', 'interactions_lag_7'
        ]

        # Check if all features exist in the dataframe
        available_features = [col for col in feature_cols if col in train_df.columns]
        print(f"\nUsing {len(available_features)} features out of {len(feature_cols)} proposed features")
        if len(available_features) < len(feature_cols):
            missing_features = set(feature_cols) - set(available_features)
            print(f"Missing features: {missing_features}")

        X_train = train_df[available_features]
        y_train = train_df['interactions']
        X_test = test_df[available_features]
        y_test = test_df['interactions']

        # Print feature statistics
        print("\nFeature statistics:")
        print(X_train.describe().transpose())

        # Check for any infinite or NaN values
        print("\nChecking for invalid values in training data:")
        print(f"NaN values in X_train: {np.isnan(X_train).sum().sum()}")
        print(f"Inf values in X_train: {np.isinf(X_train).sum().sum()}")

        # Replace any remaining NaN or infinite values
        X_train = X_train.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0)

        # Train XGBoost model
        print("\nTraining XGBoost model...")
        xgb_model = xgb.XGBRegressor(
            objective='reg:squarederror',
            n_estimators=200,
            learning_rate=0.05,
            max_depth=6,
            min_child_weight=3,
            subsample=0.8,
            colsample_bytree=0.8,
            gamma=0.1,
            reg_alpha=0.1,
            reg_lambda=1,
            random_state=42
        )

        # Train the model
        xgb_model.fit(
            X_train,
            y_train,
            eval_set=[(X_train, y_train), (X_test, y_test)],
            # eval_metric=['rmse', 'mae'],
            # early_stopping_rounds=20,
            verbose=True
        )

        # Make predictions
        y_pred_train = xgb_model.predict(X_train)
        y_pred_test = xgb_model.predict(X_test)

        # Evaluate the model
        def evaluate_model(y_true, y_pred, name=""):
            mse = mean_squared_error(y_true, y_pred)
            rmse = np.sqrt(mse)
            mae = mean_absolute_error(y_true, y_pred)
            r2 = r2_score(y_true, y_pred)

            print(f"\n{name} Evaluation Metrics:")
            print(f"MSE: {mse:.4f}")
            print(f"RMSE: {rmse:.4f}")
            print(f"MAE: {mae:.4f}")
            print(f"R²: {r2:.4f}")

            # Also calculate median absolute error as it's less sensitive to outliers
            med_ae = np.median(np.abs(y_true - y_pred))
            print(f"Median Absolute Error: {med_ae:.4f}")

            return {'mse': mse, 'rmse': rmse, 'mae': mae, 'r2': r2, 'med_ae': med_ae}

        train_metrics = evaluate_model(y_train, y_pred_train, "Training")
        test_metrics = evaluate_model(y_test, y_pred_test, "Test")

        # Feature importance
        print("\nFeature Importance:")
        feature_importance = pd.DataFrame({
            'Feature': feature_cols,
            'Importance': xgb_model.feature_importances_
        }).sort_values('Importance', ascending=False)
        print(feature_importance)

        # Hyperparameter tuning with GridSearchCV
        def tune_hyperparameters(X, y):
            print("\nPerforming hyperparameter tuning...")
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [3, 4, 5],
                'learning_rate': [0.01, 0.1, 0.2],
                'subsample': [0.7, 0.8, 0.9],
                'colsample_bytree': [0.7, 0.8, 0.9]
            }

            # For demonstration, we'll use a smaller grid and fewer CV folds
            # In practice, you'd want more comprehensive tuning
            param_grid = {
                'n_estimators': [50, 100],
                'max_depth': [3, 5],
                'learning_rate': [0.1, 0.2]
            }

            xgb_grid = GridSearchCV(
                estimator=xgb.XGBRegressor(objective='reg:squarederror', random_state=42),
                param_grid=param_grid,
                scoring='neg_mean_squared_error',
                cv=3,
                n_jobs=-1,
                verbose=1
            )

            xgb_grid.fit(X, y)

            print(f"\nBest parameters: {xgb_grid.best_params_}")
            print(f"Best RMSE: {np.sqrt(-xgb_grid.best_score_):.4f}")

            return xgb_grid.best_estimator_

        # Uncomment to perform hyperparameter tuning
        # best_model = tune_hyperparameters(X_train, y_train)
        # y_pred_best = best_model.predict(X_test)
        # best_test_metrics = evaluate_model(y_test, y_pred_best, "Best Model Test")

        # Visualize predictions vs actual values
        plt.figure(figsize=(10, 6))
        plt.scatter(y_test, y_pred_test, alpha=0.5)
        plt.plot([0, max(y_test.max(), y_pred_test.max())],
                 [0, max(y_test.max(), y_pred_test.max())],
                 'r--')
        plt.xlabel('Actual Interactions')
        plt.ylabel('Predicted Interactions')
        plt.title('XGBoost: Predicted vs Actual Interactions')
        plt.tight_layout()
        plt.savefig('xgboost_prediction_performance.png')

        # Time series visualization for a few sample CVEs
        def plot_cve_predictions(df, cve_ids, y_pred):
            plt.figure(figsize=(14, 8))

            for i, cve_id in enumerate(cve_ids):
                cve_data = df[df['cve_id'] == cve_id].copy()
                if len(cve_data) > 0:
                    cve_data = cve_data.sort_values('interaction_day')

                    # Get corresponding predictions
                    cve_indices = cve_data.index
                    cve_preds = [y_pred[df.index.get_loc(idx)] for idx in cve_indices if idx in df.index]

                    if len(cve_preds) == len(cve_data):
                        plt.subplot(len(cve_ids), 1, i + 1)
                        plt.plot(cve_data['interaction_day'], cve_data['interactions'], 'b-', label='Actual')
                        plt.plot(cve_data['interaction_day'], cve_preds, 'r--', label='Predicted')
                        plt.title(f'CVE ID: {cve_id}')
                        plt.ylabel('Interactions')
                        if i == len(cve_ids) - 1:
                            plt.xlabel('Date')
                        plt.legend()

            plt.tight_layout()
            plt.savefig('cve_time_series_predictions.png')

        # Select a few sample CVEs from test set
        # sample_cves = test_df['cve_id'].unique()[:3]
        sample_cves = df[test_df['cve_id'] == '' ]
        if len(sample_cves) > 0:
            plot_cve_predictions(test_df, sample_cves, y_pred_test)

        # Additional analysis: Distribution of prediction errors
        errors = y_test - y_pred_test
        plt.figure(figsize=(10, 6))
        plt.hist(errors, bins=30, alpha=0.7)
        plt.axvline(x=0, color='r', linestyle='--')
        plt.xlabel('Prediction Error (Actual - Predicted)')
        plt.ylabel('Frequency')
        plt.title('Distribution of Prediction Errors')
        plt.grid(True, alpha=0.3)
        plt.savefig('prediction_error_distribution.png')

        # Analyze errors by feature values
        def analyze_errors_by_feature(X, errors, feature_name):
            if feature_name in X.columns:
                data = pd.DataFrame({
                    'feature_value': X[feature_name],
                    'abs_error': np.abs(errors)
                })

                # Group by binned feature values
                if data['feature_value'].nunique() > 10:
                    data['binned'] = pd.qcut(data['feature_value'], 10, duplicates='drop')
                    grouped = data.groupby('binned')['abs_error'].mean().reset_index()
                    plt.figure(figsize=(10, 6))
                    plt.bar(grouped['binned'].astype(str), grouped['abs_error'])
                else:
                    grouped = data.groupby('feature_value')['abs_error'].mean().reset_index()
                    plt.figure(figsize=(10, 6))
                    plt.bar(grouped['feature_value'].astype(str), grouped['abs_error'])

                plt.xlabel(feature_name)
                plt.ylabel('Mean Absolute Error')
                plt.title(f'Error Analysis by {feature_name}')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.savefig(f'error_by_{feature_name}.png')

        # Analyze errors for a few key features
        important_features = ['days_since_reserved', 'interaction_velocity', 'mean_interactions']
        for feature in important_features:
            analyze_errors_by_feature(X_test, errors, feature)

        print("\nModel prediction complete and evaluation metrics calculated.")
        print(
            "Visualization files saved: xgboost_prediction_performance.png, cve_time_series_predictions.png, and prediction_error_distribution.png")

        # Save model for future use
        xgb_model.save_model('xgboost_cve_interaction_model.json')
        print("\nModel saved to 'xgboost_cve_interaction_model.json'")

        # Function to make predictions for future dates
        def predict_future_interactions(model, cve_id, latest_data, days_to_predict=30):
            """
            Predict future interactions for a specific CVE

            Parameters:
            - model: Trained XGBoost model
            - cve_id: The CVE ID to predict for
            - latest_data: DataFrame containing the most recent data
            - days_to_predict: Number of days to forecast

            Returns:
            - DataFrame with predicted interactions
            """
            # Filter data for this CVE
            cve_data = latest_data[latest_data['cve_id'] == cve_id].copy().sort_values('interaction_day')

            if len(cve_data) == 0:
                print(f"No data found for CVE {cve_id}")
                return None

            # Get the latest date and features
            last_date = cve_data['interaction_day'].max()

            # Create future dates
            future_dates = pd.date_range(start=last_date + pd.Timedelta(days=1),
                                         periods=days_to_predict, freq='D')

            # Initialize predictions DataFrame
            predictions = []

            # For each future date, generate features and predict
            current_data = cve_data.copy()

            for future_date in future_dates:
                # Create a new row with the future date
                new_row = {
                    'cve_id': cve_id,
                    'interaction_day': future_date,
                    'date_reserved': cve_data['date_reserved'].iloc[0]
                }

                # Calculate temporal features
                new_row['day_of_week'] = future_date.dayofweek
                new_row['month'] = future_date.month
                new_row['year'] = future_date.year
                new_row['quarter'] = future_date.quarter
                new_row['week_of_year'] = future_date.isocalendar()[1]
                new_row['is_weekend'] = 1 if future_date.dayofweek >= 5 else 0

                # Time-based features
                new_row['days_since_reserved'] = (future_date - new_row['date_reserved']).days
                new_row['weeks_since_reserved'] = new_row['days_since_reserved'] // 7
                new_row['log_days_since_reserved'] = np.log1p(new_row['days_since_reserved'])

                # Add most recent statistics
                for col in ['mean_interactions', 'max_interactions', 'min_interactions',
                            'std_interactions', 'median_interactions', 'interaction_days',
                            'interaction_span_days', 'avg_daily_volume', 'interaction_density',
                            'first_interaction_date', 'last_interaction_date']:
                    if col in current_data.columns:
                        new_row[col] = current_data[col].iloc[-1]

                # Update last_interaction_date
                new_row['last_interaction_date'] = future_date

                # Add reservation date features
                new_row['reserved_year'] = new_row['date_reserved'].year
                new_row['reserved_month'] = new_row['date_reserved'].month
                new_row['reserved_quarter'] = (new_row['date_reserved'].month - 1) // 3 + 1

                # Time since first interaction
                new_row['days_since_first_interaction'] = (future_date - new_row['first_interaction_date']).days

                # Add lag features from previous predictions
                for lag in [1, 2, 3, 7]:
                    lag_idx = -lag
                    if len(predictions) >= lag:
                        new_row[f'interactions_lag_{lag}'] = predictions[lag_idx]['predicted_interactions']
                    elif len(current_data) >= lag:
                        new_row[f'interactions_lag_{lag}'] = current_data['interactions'].iloc[-lag]
                    else:
                        new_row[f'interactions_lag_{lag}'] = 0

                # Create DataFrame for this prediction
                pred_df = pd.DataFrame([new_row])

                # Ensure all needed columns are present
                for col in available_features:
                    if col not in pred_df.columns:
                        pred_df[col] = 0

                # Make prediction
                X_pred = pred_df[available_features]
                X_pred = X_pred.replace([np.inf, -np.inf], np.nan).fillna(0)
                prediction = model.predict(X_pred)[0]

                # Store result
                new_row['predicted_interactions'] = max(0, round(prediction))
                predictions.append(new_row)

                # For next iteration, update "current_data" with this prediction
                pred_row = pred_df.copy()
                pred_row['interactions'] = new_row['predicted_interactions']
                current_data = pd.concat([current_data, pred_row], ignore_index=True)

            return pd.DataFrame(predictions)

        # Example of predicting future interactions for a sample CVE
        if len(test_df['cve_id'].unique()) > 0:
            sample_cve = test_df['cve_id'].unique()[0]
            print(f"\nPredicting future interactions for sample CVE: {sample_cve}")
            future_predictions = predict_future_interactions(xgb_model, sample_cve, df)

            if future_predictions is not None:
                print("\nPredicted future interactions:")
                print(future_predictions[['interaction_day', 'predicted_interactions']].head())

                # Plot historical and predicted interactions
                plt.figure(figsize=(12, 6))

                # Historical data
                historical = df[df['cve_id'] == sample_cve].sort_values('interaction_day')
                plt.plot(historical['interaction_day'], historical['interactions'], 'b-', label='Historical')

                # Predicted data
                plt.plot(future_predictions['interaction_day'], future_predictions['predicted_interactions'], 'r--',
                         label='Predicted')

                plt.xlabel('Date')
                plt.ylabel('Interactions')
                plt.title(f'Historical and Predicted Interactions for {sample_cve}')
                plt.legend()
                plt.grid(True, alpha=0.3)
                plt.savefig('future_predictions.png')
                print("Future predictions visualization saved to 'future_predictions.png'")

        # Conclusion
        print("\nConclusion:")
        print(
            "XGBoost was used to predict the number of interactions for CVEs based on temporal features and CVE characteristics.")
        print(f"The model achieved a test RMSE of {test_metrics['rmse']:.4f} and R² of {test_metrics['r2']:.4f}")
        print(f"Key predictive features: {', '.join(feature_importance['Feature'].head(5).tolist())}")
        print("\nThe model can now be used to:")
        print("1. Predict interactions for existing CVEs in future time periods")
        print("2. Identify which factors most strongly influence CVE interaction patterns")
        print("3. Help prioritize resources for addressing high-activity CVEs")